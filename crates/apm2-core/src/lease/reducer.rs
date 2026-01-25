//! Lease lifecycle reducer implementation.

use std::collections::HashMap;

use prost::Message;
use serde::{Deserialize, Serialize};

use super::error::LeaseError;
use super::state::{Lease, LeaseState, ReleaseReason};
use crate::events::{LeaseEvent, lease_event};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

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

    /// Returns all leases that have expired by the given time but haven't been
    /// marked as expired yet (still in Active state).
    #[must_use]
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

        // Create the lease
        let lease = Lease::new(
            lease_id.clone(),
            work_id.clone(),
            event.actor_id,
            event.issued_at,
            event.expires_at,
            event.registrar_signature,
        );

        // Insert lease and track active lease for work
        self.state.leases.insert(lease_id.clone(), lease);
        self.state.active_leases_by_work.insert(work_id, lease_id);

        Ok(())
    }

    /// Handles a lease renewed event.
    fn handle_renewed(&mut self, event: crate::events::LeaseRenewed) -> Result<(), LeaseError> {
        let lease_id = &event.lease_id;

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

        // Apply renewal
        lease.expires_at = event.new_expires_at;
        lease.renewal_count += 1;
        // Use the new expiration time minus old expiration as a proxy for
        // "when" (we don't have an explicit timestamp in the renewal event)
        lease.last_renewed_at = Some(event.new_expires_at);
        // Update signature to the latest
        lease.registrar_signature = event.registrar_signature;

        Ok(())
    }

    /// Handles a lease released event.
    fn handle_released(
        &mut self,
        event: &crate::events::LeaseReleased,
        timestamp: u64,
    ) -> Result<(), LeaseError> {
        let lease_id = &event.lease_id;

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

        // Apply expiration
        lease.state = LeaseState::Expired;
        lease.terminated_at = Some(event.expired_at);

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
            Some(lease_event::Event::Renewed(e)) => self.handle_renewed(e),
            Some(lease_event::Event::Released(ref e)) => self.handle_released(e, timestamp),
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

    /// Creates a `LeaseIssued` event payload.
    #[must_use]
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
        };
        let event = LeaseEvent {
            event: Some(lease_event::Event::Issued(issued)),
        };
        event.encode_to_vec()
    }

    /// Creates a `LeaseRenewed` event payload.
    #[must_use]
    pub fn lease_renewed_payload(
        lease_id: &str,
        new_expires_at: u64,
        registrar_signature: Vec<u8>,
    ) -> Vec<u8> {
        let renewed = LeaseRenewed {
            lease_id: lease_id.to_string(),
            new_expires_at,
            registrar_signature,
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
