//! Lease lifecycle reducer implementation.

use std::collections::HashMap;

use prost::Message;
use serde::{Deserialize, Serialize};

use super::error::LeaseError;
use super::state::{Lease, LeaseState, ReleaseReason};
use crate::events::{LeaseEvent, lease_event};
use crate::htf::HtfTick;
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

const MAX_ID_LEN: usize = 128;
const MAX_SIG_LEN: usize = 512;

/// State maintained by the lease reducer.
///
/// Tracks all leases and provides efficient lookup by lease ID and work ID.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseReducerState {
    /// Map of lease ID to lease.
    pub leases: HashMap<String, Lease>,

    /// Map of work ID to active lease ID (only one lease per work allowed).
    /// This is the primary enforcement mechanism for at-most-one semantics.
    pub active_leases_by_work: HashMap<String, String>,
}

impl LeaseReducerState {
    /// Creates a new empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of leases (including terminated).
    #[must_use]
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// Returns `true` if there are no leases.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// Returns the lease for a given ID, if it exists.
    #[must_use]
    pub fn get(&self, lease_id: &str) -> Option<&Lease> {
        self.leases.get(lease_id)
    }

    /// Returns the active lease for a work ID, if one exists.
    #[must_use]
    pub fn get_active_lease_for_work(&self, work_id: &str) -> Option<&Lease> {
        self.active_leases_by_work
            .get(work_id)
            .and_then(|lease_id| self.leases.get(lease_id))
    }

    /// Returns the number of active leases.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_leases_by_work.len()
    }

    /// Returns the number of released leases.
    #[must_use]
    pub fn released_count(&self) -> usize {
        self.leases
            .values()
            .filter(|l| l.state == LeaseState::Released)
            .count()
    }

    /// Returns the number of expired leases.
    #[must_use]
    pub fn expired_count(&self) -> usize {
        self.leases
            .values()
            .filter(|l| l.state == LeaseState::Expired)
            .count()
    }

    /// Returns all active leases.
    #[must_use]
    pub fn active_leases(&self) -> Vec<&Lease> {
        self.active_leases_by_work
            .values()
            .filter_map(|id| self.leases.get(id))
            .collect()
    }

    /// Returns all leases for a given actor.
    #[must_use]
    pub fn leases_by_actor(&self, actor_id: &str) -> Vec<&Lease> {
        self.leases
            .values()
            .filter(|l| l.actor_id == actor_id)
            .collect()
    }

    /// Returns all leases that have expired by the given tick but haven't been
    /// marked as expired yet (still in Active state).
    ///
    /// This is the RFC-0016 HTF compliant method using monotonic ticks.
    /// Wall time changes do not affect this check.
    ///
    /// # SEC-CTRL-FAC-0015: Fail-Closed Behavior
    ///
    /// Leases without tick-based timing will be included in the result
    /// (treated as expired) per fail-closed security policy.
    #[must_use]
    pub fn get_expired_but_active_at_tick(&self, current_tick: &HtfTick) -> Vec<&Lease> {
        self.leases
            .values()
            .filter(|l| l.is_expired_at_tick(current_tick))
            .collect()
    }

    /// Returns all leases that have expired by the given time but haven't been
    /// marked as expired yet (still in Active state).
    ///
    /// **DEPRECATED**: This method uses wall time which can be manipulated.
    /// Use [`LeaseReducerState::get_expired_but_active_at_tick`] for RFC-0016
    /// HTF compliant expiry detection.
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use get_expired_but_active_at_tick for tick-based expiry (RFC-0016 HTF)"
    )]
    #[allow(deprecated)]
    pub fn get_expired_but_active(&self, current_time: u64) -> Vec<&Lease> {
        self.leases
            .values()
            .filter(|l| l.is_expired_at(current_time))
            .collect()
    }

    /// Checks if a work item has an active lease.
    #[must_use]
    pub fn has_active_lease(&self, work_id: &str) -> bool {
        self.active_leases_by_work.contains_key(work_id)
    }

    /// Returns the number of terminal (released or expired) leases.
    #[must_use]
    pub fn terminal_count(&self) -> usize {
        self.leases.values().filter(|l| l.is_terminal()).count()
    }

    /// Removes all terminal (released/expired) leases from state.
    ///
    /// Returns the number of leases pruned. This prevents unbounded memory
    /// growth in long-running systems. The ledger retains full history.
    pub fn prune_terminal_leases(&mut self) -> usize {
        let terminal_ids: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, l)| l.is_terminal())
            .map(|(id, _)| id.clone())
            .collect();

        let count = terminal_ids.len();
        for id in terminal_ids {
            self.leases.remove(&id);
        }
        count
    }

    /// Removes terminal leases that were terminated before the given timestamp.
    ///
    /// Returns the number of leases pruned. Useful for retaining recent
    /// terminal leases while pruning older ones.
    pub fn prune_terminal_leases_before(&mut self, before_timestamp: u64) -> usize {
        let terminal_ids: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, l)| {
                l.is_terminal() && l.terminated_at.is_some_and(|t| t < before_timestamp)
            })
            .map(|(id, _)| id.clone())
            .collect();

        let count = terminal_ids.len();
        for id in terminal_ids {
            self.leases.remove(&id);
        }
        count
    }
}

/// Reducer for lease lifecycle events.
///
/// Processes lease events and maintains the state of all leases.
/// Enforces the at-most-one lease per work item invariant.
///
/// # State Machine
///
/// ```text
/// (none) --LeaseIssued--> Active
/// Active --LeaseRenewed--> Active (extended expiration)
/// Active --LeaseReleased--> Released
/// Active --LeaseExpired--> Expired
/// ```
///
/// # Security Properties
///
/// - All lease operations require a registrar signature (verified by caller)
/// - Duplicate lease issuance for the same work is rejected
/// - Only active leases can be renewed, released, or expired
///
/// # Trust Boundary: Signature Verification
///
/// This reducer checks that `registrar_signature` is non-empty but does NOT
/// perform cryptographic verification. The trust model assumes:
///
/// 1. **Ledger is append-only and authenticated**: Events are verified by the
///    Command Handler layer *before* being appended to the ledger.
/// 2. **Replay from trusted source**: When replaying the ledger, events are
///    sourced from a trusted ledger instance that has already validated
///    signatures.
///
/// If the ledger may be replicated from untrusted peers, inject a `Verifier`
/// trait to cryptographically verify signatures during replay.
///
/// # Trust Boundary: Replay Protection
///
/// This reducer relies on the ledger layer for replay protection. If terminal
/// leases are pruned (via `prune_terminal_leases`), the reducer no longer has
/// memory of those lease IDs. Replay protection MUST be enforced at the ledger
/// layer through:
///
/// 1. **Event deduplication**: The ledger must reject duplicate events before
///    they reach the reducer.
/// 2. **Monotonic event ordering**: Events must be processed in order, and the
///    ledger must not replay already-processed events.
///
/// If the reducer is replayed from a ledger that doesn't guarantee
/// deduplication, pruned lease IDs could be re-issued. This is by design -
/// the reducer is a pure state machine, not a deduplication authority.
#[derive(Debug, Default)]
pub struct LeaseReducer {
    state: LeaseReducerState,
}

impl LeaseReducer {
    /// Creates a new lease reducer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles a lease issued event.
    fn handle_issued(&mut self, event: crate::events::LeaseIssued) -> Result<(), LeaseError> {
        let lease_id = event.lease_id.clone();
        let work_id = event.work_id.clone();

        // Validate limits
        if lease_id.len() > MAX_ID_LEN {
            return Err(LeaseError::InvalidInput {
                field: "lease_id".to_string(),
                reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
            });
        }
        if work_id.len() > MAX_ID_LEN {
            return Err(LeaseError::InvalidInput {
                field: "work_id".to_string(),
                reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
            });
        }
        if event.actor_id.len() > MAX_ID_LEN {
            return Err(LeaseError::InvalidInput {
                field: "actor_id".to_string(),
                reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
            });
        }
        if event.registrar_signature.len() > MAX_SIG_LEN {
            return Err(LeaseError::InvalidInput {
                field: "registrar_signature".to_string(),
                reason: format!("exceeds limit of {MAX_SIG_LEN} bytes"),
            });
        }

        // Check for duplicate lease ID
        if self.state.leases.contains_key(&lease_id) {
            return Err(LeaseError::LeaseAlreadyExists { lease_id });
        }

        // Enforce at-most-one: check if work already has an active lease
        if let Some(existing_lease_id) = self.state.active_leases_by_work.get(&work_id) {
            return Err(LeaseError::WorkAlreadyLeased {
                work_id,
                existing_lease_id: existing_lease_id.clone(),
            });
        }

        // Validate signature is present (signature verification is done by
        // caller)
        if event.registrar_signature.is_empty() {
            return Err(LeaseError::MissingSignature { lease_id });
        }

        // Validate lease duration: expiration must be after issuance
        if event.expires_at <= event.issued_at {
            return Err(LeaseError::InvalidInput {
                field: "expires_at".to_string(),
                reason: format!(
                    "expires_at ({}) must be after issued_at ({})",
                    event.expires_at, event.issued_at
                ),
            });
        }

        // Create the lease with tick-based timing if available (RFC-0016 HTF).
        // If tick_rate_hz > 0, use tick-based constructor for SEC-CTRL-FAC-0015
        // compliance.
        let lease = if event.tick_rate_hz > 0 {
            Lease::new_with_ticks(
                lease_id.clone(),
                work_id.clone(),
                event.actor_id,
                event.issued_at,
                event.expires_at,
                HtfTick::new(event.issued_at_tick, event.tick_rate_hz),
                HtfTick::new(event.expires_at_tick, event.tick_rate_hz),
                event.registrar_signature,
            )
        } else {
            // Legacy path: no tick data available. SEC-CTRL-FAC-0015 fail-closed
            // will treat this lease as expired when checked with tick-based logic.
            Lease::new(
                lease_id.clone(),
                work_id.clone(),
                event.actor_id,
                event.issued_at,
                event.expires_at,
                event.registrar_signature,
            )
        };

        // Insert lease and track active lease for work
        self.state.leases.insert(lease_id.clone(), lease);
        self.state.active_leases_by_work.insert(work_id, lease_id);

        Ok(())
    }

    /// Handles a lease renewed event.
    fn handle_renewed(
        &mut self,
        event: crate::events::LeaseRenewed,
        timestamp: u64,
    ) -> Result<(), LeaseError> {
        let lease_id = &event.lease_id;

        if lease_id.len() > MAX_ID_LEN {
            return Err(LeaseError::InvalidInput {
                field: "lease_id".to_string(),
                reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
            });
        }

        let lease =
            self.state
                .leases
                .get_mut(lease_id)
                .ok_or_else(|| LeaseError::LeaseNotFound {
                    lease_id: lease_id.clone(),
                })?;

        // Can only renew active leases
        if lease.is_terminal() {
            return Err(LeaseError::LeaseAlreadyTerminal {
                lease_id: lease_id.clone(),
                current_state: lease.state.as_str().to_string(),
            });
        }

        // Renewal must extend the expiration
        if event.new_expires_at <= lease.expires_at {
            return Err(LeaseError::RenewalDoesNotExtend {
                lease_id: lease_id.clone(),
                current_expires_at: lease.expires_at,
                new_expires_at: event.new_expires_at,
            });
        }

        // Validate signature is present
        if event.registrar_signature.is_empty() {
            return Err(LeaseError::MissingSignature {
                lease_id: lease_id.clone(),
            });
        }
        if event.registrar_signature.len() > MAX_SIG_LEN {
            return Err(LeaseError::InvalidInput {
                field: "registrar_signature".to_string(),
                reason: format!("exceeds limit of {MAX_SIG_LEN} bytes"),
            });
        }

        // Apply renewal
        lease.expires_at = event.new_expires_at;
        lease.renewal_count = lease.renewal_count.saturating_add(1);
        // Use the event timestamp to record when the renewal occurred
        lease.last_renewed_at = Some(timestamp);
        // Update signature to the latest
        lease.registrar_signature = event.registrar_signature;

        // Update tick-based expiry if tick data is present (RFC-0016 HTF).
        // This ensures that renewed leases maintain tick-based expiry tracking.
        if event.tick_rate_hz > 0 {
            lease.expires_at_tick =
                Some(HtfTick::new(event.new_expires_at_tick, event.tick_rate_hz));
        }

        Ok(())
    }

    /// Handles a lease released event.
    fn handle_released(
        &mut self,
        event: &crate::events::LeaseReleased,
        actor_id: &str,
        timestamp: u64,
    ) -> Result<(), LeaseError> {
        let lease_id = &event.lease_id;

        if lease_id.len() > MAX_ID_LEN {
            return Err(LeaseError::InvalidInput {
                field: "lease_id".to_string(),
                reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
            });
        }

        let lease =
            self.state
                .leases
                .get_mut(lease_id)
                .ok_or_else(|| LeaseError::LeaseNotFound {
                    lease_id: lease_id.clone(),
                })?;

        // Can only release active leases
        if lease.is_terminal() {
            return Err(LeaseError::LeaseAlreadyTerminal {
                lease_id: lease_id.clone(),
                current_state: lease.state.as_str().to_string(),
            });
        }

        // Authorization check: Only lease holder can release
        // (Future: allow supervisors to release/abort)
        if lease.actor_id != actor_id {
            return Err(LeaseError::Unauthorized {
                lease_id: lease_id.clone(),
                actor_id: actor_id.to_string(),
            });
        }

        // Parse and validate release reason
        let reason = ReleaseReason::parse(&event.release_reason)?;

        // Apply release
        lease.state = LeaseState::Released;
        lease.release_reason = Some(reason);
        lease.terminated_at = Some(timestamp);

        // Remove from active leases index
        self.state.active_leases_by_work.remove(&lease.work_id);

        Ok(())
    }

    /// Handles a lease expired event.
    fn handle_expired(&mut self, event: &crate::events::LeaseExpired) -> Result<(), LeaseError> {
        let lease_id = &event.lease_id;

        if lease_id.len() > MAX_ID_LEN {
            return Err(LeaseError::InvalidInput {
                field: "lease_id".to_string(),
                reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
            });
        }

        let lease =
            self.state
                .leases
                .get_mut(lease_id)
                .ok_or_else(|| LeaseError::LeaseNotFound {
                    lease_id: lease_id.clone(),
                })?;

        // Can only expire active leases
        if lease.is_terminal() {
            return Err(LeaseError::LeaseAlreadyTerminal {
                lease_id: lease_id.clone(),
                current_state: lease.state.as_str().to_string(),
            });
        }

        // Validate expiration time: Cannot expire before the lease's expiration
        if event.expired_at < lease.expires_at {
            return Err(LeaseError::InvalidExpiration {
                lease_id: lease_id.clone(),
                provided: event.expired_at,
                lease_expires_at: lease.expires_at,
            });
        }

        // Apply expiration
        // Use the lease's actual expiration time for terminated_at, not the
        // event's expired_at, to prevent DoS via state pinning where an
        // attacker sets expired_at=u64::MAX to evade time-based pruning.
        lease.state = LeaseState::Expired;
        lease.terminated_at = Some(lease.expires_at);

        // Remove from active leases index
        self.state.active_leases_by_work.remove(&lease.work_id);

        Ok(())
    }

    /// Handles a lease conflict event.
    ///
    /// Lease conflicts are recorded for audit but don't change lease state
    /// directly. Resolution is handled by separate adjudication processes.
    #[allow(clippy::unused_self, clippy::missing_const_for_fn)]
    fn handle_conflict(&self, _event: &crate::events::LeaseConflict) {
        // Conflict events are primarily for audit/observability.
        // The actual resolution (which lease wins) is determined by
        // adjudication and results in LeaseReleased events for losing leases.
        // We don't need to modify state here - just acknowledge the event.
    }
}

impl Reducer for LeaseReducer {
    type State = LeaseReducerState;
    type Error = LeaseError;

    fn name(&self) -> &'static str {
        "lease-registrar"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        // Only handle lease events
        if !event.event_type.starts_with("lease.") {
            return Ok(());
        }

        let lease_event = LeaseEvent::decode(&event.payload[..])?;
        let timestamp = event.timestamp_ns;

        match lease_event.event {
            Some(lease_event::Event::Issued(e)) => self.handle_issued(e),
            Some(lease_event::Event::Renewed(e)) => self.handle_renewed(e, timestamp),
            Some(lease_event::Event::Released(ref e)) => {
                self.handle_released(e, &event.actor_id, timestamp)
            },
            Some(lease_event::Event::Expired(ref e)) => self.handle_expired(e),
            Some(lease_event::Event::Conflict(ref e)) => {
                self.handle_conflict(e);
                Ok(())
            },
            None => Ok(()),
        }
    }

    fn state(&self) -> &Self::State {
        &self.state
    }

    fn state_mut(&mut self) -> &mut Self::State {
        &mut self.state
    }

    fn reset(&mut self) {
        self.state = LeaseReducerState::default();
    }
}

/// Helper functions for creating lease event payloads.
pub mod helpers {
    use prost::Message;

    use crate::events::{
        LeaseConflict, LeaseEvent, LeaseExpired, LeaseIssued, LeaseReleased, LeaseRenewed,
        lease_event,
    };
    use crate::htf::HtfTick;

    /// Creates a `LeaseIssued` event payload with tick-based timing (RFC-0016
    /// HTF).
    ///
    /// This is the preferred function for creating lease issued events as it
    /// includes tick-based timing data required for SEC-CTRL-FAC-0015
    /// compliance.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn lease_issued_payload_with_ticks(
        lease_id: &str,
        work_id: &str,
        actor_id: &str,
        issued_at: u64,
        expires_at: u64,
        issued_at_tick: &HtfTick,
        expires_at_tick: &HtfTick,
        registrar_signature: Vec<u8>,
    ) -> Vec<u8> {
        let issued = LeaseIssued {
            lease_id: lease_id.to_string(),
            work_id: work_id.to_string(),
            actor_id: actor_id.to_string(),
            issued_at,
            expires_at,
            registrar_signature,
            // HTF time envelope reference (RFC-0016): not yet populated by this helper.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
            issued_at_tick: issued_at_tick.value(),
            expires_at_tick: expires_at_tick.value(),
            tick_rate_hz: issued_at_tick.tick_rate_hz(),
        };
        let event = LeaseEvent {
            event: Some(lease_event::Event::Issued(issued)),
        };
        event.encode_to_vec()
    }

    /// Creates a `LeaseIssued` event payload without tick-based timing.
    ///
    /// **DEPRECATED**: This function creates events without tick-based timing,
    /// which will cause leases to be treated as expired per SEC-CTRL-FAC-0015
    /// fail-closed policy. Use [`lease_issued_payload_with_ticks`] instead.
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use lease_issued_payload_with_ticks for RFC-0016 HTF compliance"
    )]
    pub fn lease_issued_payload(
        lease_id: &str,
        work_id: &str,
        actor_id: &str,
        issued_at: u64,
        expires_at: u64,
        registrar_signature: Vec<u8>,
    ) -> Vec<u8> {
        let issued = LeaseIssued {
            lease_id: lease_id.to_string(),
            work_id: work_id.to_string(),
            actor_id: actor_id.to_string(),
            issued_at,
            expires_at,
            registrar_signature,
            // HTF time envelope reference (RFC-0016): not yet populated by this helper.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
            // Legacy: tick fields set to 0 (fail-closed per SEC-CTRL-FAC-0015)
            issued_at_tick: 0,
            expires_at_tick: 0,
            tick_rate_hz: 0,
        };
        let event = LeaseEvent {
            event: Some(lease_event::Event::Issued(issued)),
        };
        event.encode_to_vec()
    }

    /// Creates a `LeaseRenewed` event payload with tick-based timing (RFC-0016
    /// HTF).
    ///
    /// This is the preferred function for creating lease renewed events as it
    /// includes tick-based timing data required for SEC-CTRL-FAC-0015
    /// compliance.
    #[must_use]
    pub fn lease_renewed_payload_with_ticks(
        lease_id: &str,
        new_expires_at: u64,
        new_expires_at_tick: &HtfTick,
        registrar_signature: Vec<u8>,
    ) -> Vec<u8> {
        let renewed = LeaseRenewed {
            lease_id: lease_id.to_string(),
            new_expires_at,
            registrar_signature,
            // HTF time envelope reference (RFC-0016): not yet populated by this helper.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
            new_expires_at_tick: new_expires_at_tick.value(),
            tick_rate_hz: new_expires_at_tick.tick_rate_hz(),
        };
        let event = LeaseEvent {
            event: Some(lease_event::Event::Renewed(renewed)),
        };
        event.encode_to_vec()
    }

    /// Creates a `LeaseRenewed` event payload without tick-based timing.
    ///
    /// **DEPRECATED**: This function creates events without tick-based timing,
    /// which will NOT update the tick-based expiry. Use
    /// [`lease_renewed_payload_with_ticks`] instead.
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use lease_renewed_payload_with_ticks for RFC-0016 HTF compliance"
    )]
    pub fn lease_renewed_payload(
        lease_id: &str,
        new_expires_at: u64,
        registrar_signature: Vec<u8>,
    ) -> Vec<u8> {
        let renewed = LeaseRenewed {
            lease_id: lease_id.to_string(),
            new_expires_at,
            registrar_signature,
            // HTF time envelope reference (RFC-0016): not yet populated by this helper.
            time_envelope_ref: None,
            // Legacy: tick fields set to 0 (no tick update)
            new_expires_at_tick: 0,
            tick_rate_hz: 0,
        };
        let event = LeaseEvent {
            event: Some(lease_event::Event::Renewed(renewed)),
        };
        event.encode_to_vec()
    }

    /// Creates a `LeaseReleased` event payload.
    #[must_use]
    pub fn lease_released_payload(lease_id: &str, release_reason: &str) -> Vec<u8> {
        let released = LeaseReleased {
            lease_id: lease_id.to_string(),
            release_reason: release_reason.to_string(),
            // HTF time envelope reference (RFC-0016): not yet populated by this helper.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
        };
        let event = LeaseEvent {
            event: Some(lease_event::Event::Released(released)),
        };
        event.encode_to_vec()
    }

    /// Creates a `LeaseExpired` event payload.
    #[must_use]
    pub fn lease_expired_payload(lease_id: &str, expired_at: u64) -> Vec<u8> {
        let expired = LeaseExpired {
            lease_id: lease_id.to_string(),
            expired_at,
        };
        let event = LeaseEvent {
            event: Some(lease_event::Event::Expired(expired)),
        };
        event.encode_to_vec()
    }

    /// Creates a `LeaseConflict` event payload.
    #[must_use]
    pub fn lease_conflict_payload(
        work_id: &str,
        conflicting_lease_ids: Vec<String>,
        resolution: &str,
    ) -> Vec<u8> {
        let conflict = LeaseConflict {
            work_id: work_id.to_string(),
            conflicting_lease_ids,
            resolution: resolution.to_string(),
        };
        let event = LeaseEvent {
            event: Some(lease_event::Event::Conflict(conflict)),
        };
        event.encode_to_vec()
    }
}
