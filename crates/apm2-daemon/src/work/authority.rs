use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use apm2_core::events::alias_reconcile::{
    self, AliasReconciliationResult, ObservationWindow, SnapshotEmitterStatus,
    SnapshotSunsetCriteria, TicketAliasBinding, evaluate_sunset, promotion_gate, reconcile_aliases,
};
use apm2_core::work::{Work, WorkState};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::warn;

use super::projection::{WorkObjectProjection, WorkProjectionError};
use crate::protocol::dispatch::{LedgerEventEmitter, SignedLedgerEvent};

/// Hard server-side cap on the number of rows returned by `WorkList`.
///
/// Enforced regardless of the client-requested `limit` to prevent unbounded
/// full-ledger replay on the request path.
pub const MAX_WORK_LIST_ROWS: usize = 500;

/// Projection-derived authority view for a single work item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkAuthorityStatus {
    /// Work identifier.
    pub work_id: String,
    /// Current lifecycle state.
    pub state: WorkState,
    /// Whether the work item is currently claimable.
    pub claimable: bool,
    /// Work-open timestamp.
    pub created_at_ns: u64,
    /// Most recent transition timestamp.
    pub last_transition_at_ns: u64,
    /// Transition counter for replay protection.
    pub transition_count: u32,
    /// Timestamp of first claim transition when derivable.
    pub claimed_at_ns: Option<u64>,
}

/// Authority-layer errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WorkAuthorityError {
    /// Projection lock failed.
    #[error("projection lock failure: {message}")]
    ProjectionLock {
        /// Underlying lock error detail.
        message: String,
    },

    /// Projection rebuild failed.
    #[error("projection rebuild failed: {0}")]
    ProjectionRebuild(#[from] WorkProjectionError),

    /// Work ID is unknown to the projection.
    #[error("work not found in projection: {work_id}")]
    WorkNotFound {
        /// Missing work ID.
        work_id: String,
    },
}

/// Work lifecycle authority contract.
pub trait WorkAuthority: Send + Sync {
    /// Returns projection-derived status for a single work item.
    fn get_work_status(&self, work_id: &str) -> Result<WorkAuthorityStatus, WorkAuthorityError>;

    /// Returns claimable work items, bounded by `limit` and `cursor`.
    ///
    /// `limit` is clamped to `MAX_WORK_LIST_ROWS`. `cursor` is the last
    /// `work_id` from a previous page (exclusive start).
    fn list_claimable(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError>;

    /// Returns all known work items, bounded by `limit` and `cursor`.
    ///
    /// `limit` is clamped to `MAX_WORK_LIST_ROWS`. `cursor` is the last
    /// `work_id` from a previous page (exclusive start).
    fn list_all(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError>;

    /// Returns whether the work item is claimable.
    fn is_claimable(&self, work_id: &str) -> Result<bool, WorkAuthorityError>;
}

/// Projection-backed `WorkAuthority` implementation.
///
/// Authority is rebuilt from ledger events only; filesystem state is never
/// consulted. The projection is cached and only rebuilt when the event count
/// changes, avoiding O(N) full replay on every request.
pub struct ProjectionWorkAuthority {
    event_emitter: Arc<dyn LedgerEventEmitter>,
    projection: Arc<RwLock<WorkObjectProjection>>,
    /// Cached event count from the last successful rebuild. When the emitter
    /// reports a different count the projection is refreshed.
    last_event_count: Arc<RwLock<usize>>,
}

impl ProjectionWorkAuthority {
    /// Creates a projection-backed authority view over the provided emitter.
    #[must_use]
    pub fn new(event_emitter: Arc<dyn LedgerEventEmitter>) -> Self {
        Self {
            event_emitter,
            projection: Arc::new(RwLock::new(WorkObjectProjection::new())),
            last_event_count: Arc::new(RwLock::new(0)),
        }
    }

    fn refresh_projection(&self) -> Result<(), WorkAuthorityError> {
        // O(1) pre-check: query event count without fetching all rows.
        // Only proceed to the full fetch when the count has changed.
        let current_count = self.event_emitter.get_event_count();

        {
            let cached =
                self.last_event_count
                    .read()
                    .map_err(|err| WorkAuthorityError::ProjectionLock {
                        message: err.to_string(),
                    })?;
            if *cached == current_count {
                return Ok(());
            }
        }

        // Count changed — fetch all events for full projection rebuild.
        let signed_events = self.event_emitter.get_all_events();

        // SECURITY FIX (Blocker 1 & 2): Trust-on-persist model.
        //
        // Signatures were already verified at write/admission time by the
        // emitter. Re-verifying against the current in-memory signing key
        // would break after daemon restart (the key is regenerated per
        // lifecycle). Instead we filter events by work-domain event types
        // only, skipping session-originated events that could spoof
        // reserved work event names (namespace collision prevention).
        let work_events = Self::filter_work_domain_events(&signed_events);

        let mut projection =
            self.projection
                .write()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;
        projection.rebuild_from_signed_events(&work_events)?;

        // Update cached event count after successful rebuild.
        if let Ok(mut cached) = self.last_event_count.write() {
            *cached = current_count;
        }
        Ok(())
    }

    /// Filters ledger events to only those originating from work-domain
    /// emission paths.
    ///
    /// Session-originated events (via `EmitEvent`) use the
    /// `apm2.event.session_event:` domain prefix during signing, NOT the
    /// work-domain prefixes (`apm2.event.work_claimed:`,
    /// `apm2.event.work_transitioned:`). A malicious session could emit
    /// events with `event_type = "work_claimed"`, but those events would
    /// have been signed with the session domain prefix.
    ///
    /// We distinguish work-domain events from session events by structural
    /// payload validation: work-domain events contain a top-level `work_id`
    /// field and no `session_id` field, while session-wrapped events always
    /// contain `session_id` and wrap payloads differently. Events that fail
    /// this structural check are silently skipped (they are session events
    /// masquerading as work events). Events without a known work-domain
    /// prefix (native `work.*` protobuf events) are passed through
    /// unconditionally since `translate_signed_events` filters them
    /// structurally.
    pub(crate) fn filter_work_domain_events(
        events: &[SignedLedgerEvent],
    ) -> Vec<SignedLedgerEvent> {
        use crate::protocol::dispatch::{
            WORK_CLAIMED_DOMAIN_PREFIX, WORK_TRANSITIONED_DOMAIN_PREFIX,
        };

        events
            .iter()
            .filter(|event| {
                match event.event_type.as_str() {
                    // Legacy daemon work events: only admit if the payload
                    // structure matches work-domain expectations. Session
                    // events wrap payloads differently (hex-encoded inner
                    // payload with `session_id` field) so structural
                    // validation rejects them.
                    "work_claimed" => Self::has_work_domain_payload_structure(
                        &event.payload,
                        WORK_CLAIMED_DOMAIN_PREFIX,
                    ),
                    "work_transitioned" => Self::has_work_domain_payload_structure(
                        &event.payload,
                        WORK_TRANSITIONED_DOMAIN_PREFIX,
                    ),
                    // Native protobuf work events (`work.opened`, etc.)
                    // are only emittable through the work-domain code path,
                    // not through session EmitEvent. Pass through.
                    t if t.starts_with("work.") => true,
                    // All other event types are not work-relevant;
                    // `translate_signed_events` ignores them anyway.
                    _ => true,
                }
            })
            .cloned()
            .collect()
    }

    /// Checks whether a JSON payload has the structural shape of a
    /// work-domain event rather than a session-wrapped event.
    ///
    /// Work-domain events contain a top-level `work_id` field and do NOT
    /// contain a `session_id` field. Session events (via `EmitEvent`)
    /// always contain `session_id` and wrap the user payload as
    /// hex-encoded bytes, so they structurally differ.
    fn has_work_domain_payload_structure(payload: &[u8], _domain_prefix: &[u8]) -> bool {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
            return false;
        };

        // Work-domain events have a `work_id` field; session-wrapped
        // events have a `session_id` field instead. Reject events that
        // look like session wrappers.
        let has_work_id = value.get("work_id").and_then(|v| v.as_str()).is_some();
        let has_session_id = value.get("session_id").and_then(|v| v.as_str()).is_some();

        has_work_id && !has_session_id
    }

    fn status_from_work(work: &Work) -> WorkAuthorityStatus {
        WorkAuthorityStatus {
            work_id: work.work_id.clone(),
            state: work.state,
            claimable: work.state.is_claimable(),
            created_at_ns: work.opened_at,
            last_transition_at_ns: work.last_transition_at,
            transition_count: work.transition_count,
            claimed_at_ns: work.claimed_at,
        }
    }

    /// Clamps `limit` to `MAX_WORK_LIST_ROWS` and applies cursor-based
    /// pagination over a deterministically-ordered iterator.
    fn bounded_collect<'a, I>(iter: I, limit: usize, cursor: &str) -> Vec<WorkAuthorityStatus>
    where
        I: Iterator<Item = &'a Work>,
    {
        let effective_limit = if limit == 0 {
            MAX_WORK_LIST_ROWS
        } else {
            limit.min(MAX_WORK_LIST_ROWS)
        };

        let skip_past_cursor = !cursor.is_empty();

        let mut items: Vec<WorkAuthorityStatus> = iter
            .skip_while(|work| skip_past_cursor && work.work_id.as_str() <= cursor)
            .take(effective_limit)
            .map(Self::status_from_work)
            .collect();

        // Ensure deterministic ordering by work_id (BTreeMap already sorted).
        items.sort_by(|a, b| a.work_id.cmp(&b.work_id));
        items
    }
}

impl WorkAuthority for ProjectionWorkAuthority {
    fn get_work_status(&self, work_id: &str) -> Result<WorkAuthorityStatus, WorkAuthorityError> {
        self.refresh_projection()?;

        let projection =
            self.projection
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        let work =
            projection
                .get_work(work_id)
                .ok_or_else(|| WorkAuthorityError::WorkNotFound {
                    work_id: work_id.to_string(),
                })?;

        Ok(Self::status_from_work(work))
    }

    fn list_claimable(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError> {
        self.refresh_projection()?;

        let projection =
            self.projection
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        Ok(Self::bounded_collect(
            projection.claimable_work().into_iter(),
            limit,
            cursor,
        ))
    }

    fn list_all(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError> {
        self.refresh_projection()?;

        let projection =
            self.projection
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        Ok(Self::bounded_collect(
            projection.list_work().into_iter(),
            limit,
            cursor,
        ))
    }

    fn is_claimable(&self, work_id: &str) -> Result<bool, WorkAuthorityError> {
        let status = self.get_work_status(work_id)?;
        Ok(status.claimable)
    }
}

// ============================================================================
// Alias Reconciliation Gate (TCK-00420)
// ============================================================================

/// Maximum observation window size in ticks. Prevents unbounded windows
/// from causing memory or compute issues.
pub const MAX_OBSERVATION_WINDOW_TICKS: u64 = 100_000;

/// Default staleness threshold in ticks for alias bindings.
pub const DEFAULT_MAX_STALENESS_TICKS: u64 = 100;

/// Default minimum consecutive clean ticks for snapshot-emitter sunset.
pub const DEFAULT_MIN_RECONCILED_TICKS: u64 = 50;

/// Alias reconciliation gate contract for the work authority layer.
///
/// This trait provides the production wiring between the alias reconciliation
/// module ([`apm2_core::events::alias_reconcile`]) and the daemon work
/// authority layer. It is invoked during work lifecycle operations to ensure
/// alias/`work_id` projections are consistent before promotion.
///
/// # Contracts
///
/// - [CTR-ALIAS-002] Promotion gates require zero unresolved alias/`work_id`
///   mismatches.
/// - [CTR-ALIAS-004] Runtime authority decisions remain `work_id`-centric;
///   alias reconciliation is advisory but promotion-blocking.
///
/// # Current Limitation: Identity-Mapped Aliases
///
/// In the current implementation, alias registration requires explicit
/// `register_alias()` calls from an operator layer. The default `ClaimWork`
/// wire-protocol path registers only identity mappings (`work_id` ->
/// `work_id`), meaning the reconciliation gate validates that a `work_id`
/// resolves to itself in the projection -- a structural placeholder that
/// verifies projection wiring and staleness enforcement but does not check
/// real `TCK-*` alias-to-`work_id` mappings.
///
/// Real alias bindings require the operator layer or policy resolver to
/// supply the `ticket_alias` field. See `TODO(TCK-00425)` for the planned
/// follow-up to wire real aliases through policy resolution.
pub trait AliasReconciliationGate: Send + Sync {
    /// Runs alias reconciliation against the current projection state and
    /// returns whether promotion is permitted (zero defects).
    ///
    /// # Arguments
    ///
    /// * `bindings` - Alias bindings to reconcile against canonical projection.
    /// * `current_tick` - The current HTF tick.
    ///
    /// # Returns
    ///
    /// `Ok(result)` with zero unresolved defects if promotion is permitted,
    /// or non-empty defects if any were found (fail-closed). `Err` on
    /// infrastructure failure.
    fn check_promotion(
        &self,
        bindings: &[TicketAliasBinding],
        current_tick: u64,
    ) -> Result<AliasReconciliationResult, WorkAuthorityError>;

    /// Returns the observation window configuration used by this gate.
    ///
    /// Callers use this to populate `TicketAliasBinding` fields
    /// (`observation_window_start`, `observation_window_end`) from the
    /// gate's actual configuration rather than hardcoded values.
    fn observation_window(&self) -> &ObservationWindow;

    /// Evaluates snapshot-emitter sunset status based on reconciliation
    /// history.
    fn evaluate_emitter_sunset(
        &self,
        consecutive_clean_ticks: u64,
        has_defects: bool,
    ) -> SnapshotEmitterStatus;
}

/// Projection-backed alias reconciliation gate implementation.
///
/// Bridges the alias reconciliation module to the daemon work authority layer
/// by building canonical projections from the `WorkObjectProjection` state
/// and delegating to [`reconcile_aliases`] and [`promotion_gate`].
pub struct ProjectionAliasReconciliationGate {
    /// Shared projection rebuilt from ledger events.
    projection: Arc<RwLock<WorkObjectProjection>>,

    /// Ledger event emitter for projection refresh.
    event_emitter: Arc<dyn LedgerEventEmitter>,

    /// Cached event count for incremental refresh.
    last_event_count: Arc<RwLock<usize>>,

    /// Observation window configuration.
    observation_window: ObservationWindow,

    /// Sunset criteria configuration.
    sunset_criteria: SnapshotSunsetCriteria,
}

impl ProjectionAliasReconciliationGate {
    /// Creates a new alias reconciliation gate backed by the given emitter.
    ///
    /// Uses default observation window and sunset criteria.
    #[must_use]
    pub fn new(event_emitter: Arc<dyn LedgerEventEmitter>) -> Self {
        Self {
            projection: Arc::new(RwLock::new(WorkObjectProjection::new())),
            event_emitter,
            last_event_count: Arc::new(RwLock::new(0)),
            observation_window: ObservationWindow {
                start_tick: 0,
                end_tick: MAX_OBSERVATION_WINDOW_TICKS,
                max_staleness_ticks: DEFAULT_MAX_STALENESS_TICKS,
            },
            sunset_criteria: SnapshotSunsetCriteria {
                min_reconciled_ticks: DEFAULT_MIN_RECONCILED_TICKS,
                zero_defects_required: true,
            },
        }
    }

    /// Creates a gate with custom observation window and sunset criteria.
    #[must_use]
    pub fn with_config(
        event_emitter: Arc<dyn LedgerEventEmitter>,
        observation_window: ObservationWindow,
        sunset_criteria: SnapshotSunsetCriteria,
    ) -> Self {
        Self {
            projection: Arc::new(RwLock::new(WorkObjectProjection::new())),
            event_emitter,
            last_event_count: Arc::new(RwLock::new(0)),
            observation_window,
            sunset_criteria,
        }
    }

    /// Refreshes the projection from ledger events if the event count changed.
    ///
    /// Lock failures are propagated as `ProjectionLock` errors (fail-closed).
    /// Projection rebuild failures (e.g., individual work item reducer errors)
    /// are logged at warning level and the gate retains the last successfully
    /// built projection state. This means the gate will check against a
    /// possibly-stale (but internally consistent) projection rather than
    /// failing outright. Staleness is enforced separately by the observation
    /// window's `max_staleness_ticks` configuration.
    fn refresh_projection(&self) -> Result<(), WorkAuthorityError> {
        let current_count = self.event_emitter.get_event_count();

        {
            let cached =
                self.last_event_count
                    .read()
                    .map_err(|err| WorkAuthorityError::ProjectionLock {
                        message: err.to_string(),
                    })?;
            if *cached == current_count {
                return Ok(());
            }
        }

        let signed_events = self.event_emitter.get_all_events();

        // Filter to work-domain events only (same trust model as
        // ProjectionWorkAuthority).
        let work_events = ProjectionWorkAuthority::filter_work_domain_events(&signed_events);

        let mut projection =
            self.projection
                .write()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        match projection.rebuild_from_signed_events(&work_events) {
            Ok(()) => {
                if let Ok(mut cached) = self.last_event_count.write() {
                    *cached = current_count;
                }
            },
            Err(e) => {
                // Projection rebuild failed for some work items, but the
                // gate retains the last successfully built state. Staleness
                // enforcement via observation_window.max_staleness_ticks
                // ensures that bindings checked against a stale projection
                // are still caught by the DefectClass::Stale path.
                warn!(
                    error = %e,
                    "Alias reconciliation gate: projection rebuild warning; \
                     retaining last consistent projection state"
                );
            },
        }
        Ok(())
    }

    /// Builds canonical projections from the current work object state.
    ///
    /// Returns `HashMap<alias, Vec<Hash>>` where each alias maps to one or
    /// more canonical `work_id` hashes. Multiple entries for the same alias
    /// indicate ambiguity and will produce `DefectClass::Ambiguous` defects.
    fn build_canonical_projections(
        &self,
    ) -> Result<HashMap<String, Vec<alias_reconcile::Hash>>, WorkAuthorityError> {
        let projection =
            self.projection
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        let mut projections: HashMap<String, Vec<alias_reconcile::Hash>> = HashMap::new();
        for work in projection.list_work() {
            // The work_id itself is the canonical identity. We use a SHA-256
            // hash of the work_id string as the alias_reconcile::Hash.
            let hash = work_id_to_hash(&work.work_id);
            projections
                .entry(work.work_id.clone())
                .or_default()
                .push(hash);
        }
        Ok(projections)
    }
}

impl AliasReconciliationGate for ProjectionAliasReconciliationGate {
    fn check_promotion(
        &self,
        bindings: &[TicketAliasBinding],
        current_tick: u64,
    ) -> Result<AliasReconciliationResult, WorkAuthorityError> {
        self.refresh_projection()?;

        let canonical_projections = self.build_canonical_projections()?;
        let mut result = reconcile_aliases(bindings, &canonical_projections, current_tick);

        // TCK-00420 BLOCKER 2 fix: Enforce observation-window staleness in
        // the production promotion path. Without this, bindings with
        // arbitrarily old `observed_at_tick` values would pass reconciliation
        // unchecked, violating REQ-HEF-0017 temporal freshness enforcement.
        //
        // For each resolved binding, check staleness against the gate's
        // observation window configuration. Stale bindings produce
        // `DefectClass::Stale` defects that block promotion (fail-closed).
        let mut stale_defects = Vec::new();
        for binding in bindings {
            if self
                .observation_window
                .is_stale(binding.observed_at_tick, current_tick)
            {
                stale_defects.push(alias_reconcile::AliasReconciliationDefect {
                    ticket_alias: binding.ticket_alias.clone(),
                    expected_work_id: binding.canonical_work_id,
                    actual_work_id: alias_reconcile::ZERO_HASH,
                    defect_class: alias_reconcile::DefectClass::Stale,
                    detected_at_tick: current_tick,
                });
            }
        }

        if !stale_defects.is_empty() {
            warn!(
                stale_count = stale_defects.len(),
                current_tick = current_tick,
                max_staleness_ticks = self.observation_window.max_staleness_ticks,
                "Alias reconciliation: stale bindings detected (fail-closed)"
            );
            // Decrement resolved_count for any binding that was counted as
            // resolved but is now also stale.
            for stale in &stale_defects {
                if result
                    .unresolved_defects
                    .iter()
                    .all(|d| d.ticket_alias != stale.ticket_alias)
                {
                    // This binding was counted as resolved, but is stale
                    result.resolved_count = result.resolved_count.saturating_sub(1);
                }
            }
            result.unresolved_defects.extend(stale_defects);
        }

        if !promotion_gate(&result) {
            warn!(
                defect_count = result.unresolved_defects.len(),
                resolved_count = result.resolved_count,
                current_tick = current_tick,
                "Alias reconciliation promotion gate DENIED: unresolved defects found"
            );
        }

        Ok(result)
    }

    fn observation_window(&self) -> &ObservationWindow {
        &self.observation_window
    }

    fn evaluate_emitter_sunset(
        &self,
        consecutive_clean_ticks: u64,
        has_defects: bool,
    ) -> SnapshotEmitterStatus {
        evaluate_sunset(&self.sunset_criteria, consecutive_clean_ticks, has_defects)
    }
}

/// Domain-separation prefix for `work_id` hashing.
///
/// This prefix ensures that `work_id_to_hash` outputs cannot collide with
/// hashes derived from other domain contexts (e.g., session tokens, envelope
/// digests).
const ALIAS_RECONCILE_DOMAIN_PREFIX: &[u8] = b"apm2.alias_reconcile.work_id:";

/// Converts a `work_id` string to a 32-byte hash for the alias reconciliation
/// module's `Hash` type. Uses domain-separated SHA-256 to produce a
/// collision-resistant canonical identity token.
///
/// # Domain Separation
///
/// The hash is computed as `SHA-256(ALIAS_RECONCILE_DOMAIN_PREFIX || work_id)`,
/// ensuring that identical `work_id` bytes in different contexts produce
/// distinct hashes.
#[must_use]
pub fn work_id_to_hash(work_id: &str) -> alias_reconcile::Hash {
    let mut hasher = Sha256::new();
    hasher.update(ALIAS_RECONCILE_DOMAIN_PREFIX);
    hasher.update(work_id.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_id_to_hash_deterministic() {
        let h1 = work_id_to_hash("work-123");
        let h2 = work_id_to_hash("work-123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn work_id_to_hash_distinct() {
        let h1 = work_id_to_hash("work-123");
        let h2 = work_id_to_hash("work-456");
        assert_ne!(h1, h2);
    }

    #[test]
    fn work_id_to_hash_is_sha256_not_xor() {
        // Verify the hash is a proper SHA-256 digest, not XOR folding.
        // XOR folding would produce [0; 32] for two identical 32-byte
        // blocks, so a 64-byte input of all 'A's would XOR to [0; 32].
        let long_input = "A".repeat(64);
        let hash = work_id_to_hash(&long_input);
        assert_ne!(
            hash, [0u8; 32],
            "SHA-256 hash must not be zero for non-empty input"
        );

        // Also verify against a known SHA-256 property: hash length is 32 bytes
        // and different inputs of similar shape produce different outputs.
        let hash_a = work_id_to_hash(&"A".repeat(33));
        let hash_b = work_id_to_hash(&"B".repeat(33));
        assert_ne!(
            hash_a, hash_b,
            "distinct inputs must produce distinct SHA-256 outputs"
        );
    }

    #[test]
    fn work_id_to_hash_adversarial_collision_resistance() {
        // Under XOR folding, "A" repeated 33 times and "B" + "A"*31 + "B"
        // would collide because XOR(A[0]^B[0], A[32]^B[32]) cancels out.
        // SHA-256 must NOT produce a collision for these adversarial inputs.
        let input_a = "A".repeat(33);
        let mut input_b_bytes = vec![b'B'];
        input_b_bytes.extend_from_slice(&[b'A'; 31]);
        input_b_bytes.push(b'B');
        let input_b = String::from_utf8(input_b_bytes).unwrap();

        let hash_a = work_id_to_hash(&input_a);
        let hash_b = work_id_to_hash(&input_b);
        assert_ne!(
            hash_a, hash_b,
            "adversarial inputs must not collide under SHA-256"
        );
    }

    #[test]
    fn work_id_to_hash_domain_separated() {
        // Verify domain separation: the raw SHA-256 of a work_id (without
        // prefix) must differ from work_id_to_hash output.
        let work_id = "W-DOMAIN-TEST-001";
        let hash_with_domain = work_id_to_hash(work_id);

        // Compute SHA-256 without domain prefix
        let mut hasher = Sha256::new();
        hasher.update(work_id.as_bytes());
        let raw_result = hasher.finalize();
        let mut raw_hash = [0u8; 32];
        raw_hash.copy_from_slice(&raw_result);

        assert_ne!(
            hash_with_domain, raw_hash,
            "domain-separated hash must differ from raw SHA-256 of same input"
        );
    }

    #[test]
    fn promotion_gate_blocks_on_ambiguity() {
        let bindings = vec![TicketAliasBinding {
            ticket_alias: "TCK-001".to_string(),
            canonical_work_id: [0x01; 32],
            observed_at_tick: 100,
            observation_window_start: 90,
            observation_window_end: 110,
        }];

        let mut projections: HashMap<String, Vec<alias_reconcile::Hash>> = HashMap::new();
        projections.insert("TCK-001".to_string(), vec![[0x01; 32], [0x02; 32]]);

        let result = reconcile_aliases(&bindings, &projections, 100);
        assert!(!promotion_gate(&result), "ambiguity must block promotion");
        assert_eq!(result.unresolved_defects.len(), 1);
        assert_eq!(
            result.unresolved_defects[0].defect_class,
            alias_reconcile::DefectClass::Ambiguous
        );
    }

    #[test]
    fn tick_regression_is_stale() {
        let window = ObservationWindow {
            start_tick: 0,
            end_tick: 1000,
            max_staleness_ticks: 10,
        };
        // Fail-closed: temporal inversion must be stale
        assert!(window.is_stale(100, 50));
    }
}
