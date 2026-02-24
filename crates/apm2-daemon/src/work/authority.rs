use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use apm2_core::events::alias_reconcile::{
    self, AliasReconciliationResult, ObservationWindow, SnapshotEmitterStatus,
    SnapshotSunsetCriteria, TicketAliasBinding, evaluate_sunset, promotion_gate, reconcile_aliases,
};
use apm2_core::work::{Work, WorkState};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::warn;

use super::projection::{WorkDependencyDiagnostic, WorkObjectProjection, WorkProjectionError};
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
    /// Whether implementer claim is blocked by unsatisfied incoming BLOCKS
    /// dependencies.
    pub implementer_claim_blocked: bool,
    /// Structured dependency diagnostics for consumers such as doctor/work
    /// status.
    pub dependency_diagnostics: Vec<WorkDependencyDiagnostic>,
    // STEP_10: FAC identity chain surface.
    /// Latest changeset digest (32 bytes) from `ChangeSetPublished`.
    pub latest_changeset_digest: Option<[u8; 32]>,
    /// Event ID of the `ChangeSetPublished` that established the latest
    /// changeset identity binding.
    pub changeset_published_event_id: Option<String>,
    /// CAS hash (32 bytes) of the `ChangeSetBundleV1` for the latest
    /// changeset.
    pub bundle_cas_hash: Option<[u8; 32]>,
    /// Gate status for the latest changeset digest.
    pub gate_status: Option<String>,
    /// Review status for the latest changeset digest.
    pub review_status: Option<String>,
    /// Merge status for the latest changeset digest.
    pub merge_status: Option<String>,
    /// Number of identity-chain defects recorded for this work item.
    pub identity_chain_defect_count: u32,
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

    /// Returns a shared handle to the underlying `WorkObjectProjection`.
    ///
    /// Used by related authority components (for example alias reconciliation)
    /// to avoid maintaining redundant projection state from the same emitter.
    #[must_use]
    pub(crate) fn shared_projection(&self) -> Arc<RwLock<WorkObjectProjection>> {
        Arc::clone(&self.projection)
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
                        &event.event_type,
                        &event.work_id,
                        &event.payload,
                        WORK_CLAIMED_DOMAIN_PREFIX,
                    ),
                    "work_transitioned" => Self::has_work_domain_payload_structure(
                        &event.event_type,
                        &event.work_id,
                        &event.payload,
                        WORK_TRANSITIONED_DOMAIN_PREFIX,
                    ),
                    // Work graph edge events are authority-relevant and must
                    // not be admitted from session-wrapped EmitEvent payloads.
                    t if Self::is_work_graph_edge_event_type(t) => {
                        Self::has_authoritative_work_graph_payload_structure(&event.payload)
                    },
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

    /// Returns true when `event_type` denotes a work graph edge event.
    fn is_work_graph_edge_event_type(event_type: &str) -> bool {
        let normalized = event_type
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();

        matches!(
            normalized.as_str(),
            "workgraphedgeadded"
                | "workgraphedgeremoved"
                | "workgraphedgewaived"
                | "workedgeadded"
                | "workedgeremoved"
                | "workedgewaived"
        )
    }

    /// Rejects session-wrapped JSON envelopes for work graph edge events.
    ///
    /// Session `EmitEvent` envelopes include both `session_id` and wrapped
    /// `payload` fields. Authoritative graph events are either protobuf bytes
    /// or direct JSON edge payloads without this wrapper shape.
    fn has_authoritative_work_graph_payload_structure(payload: &[u8]) -> bool {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
            // Non-JSON payloads are expected for protobuf graph events.
            return true;
        };

        let session_id_field = value.get("session_id").and_then(|v| v.as_str());
        let has_session_id = session_id_field.is_some();
        let has_wrapped_payload = value.get("payload").and_then(|v| v.as_str()).is_some();

        !(has_session_id && has_wrapped_payload)
    }

    /// Checks whether a JSON payload has the structural shape of a
    /// work-domain event rather than a session-wrapped event.
    ///
    /// Work-domain events contain a top-level `work_id` field. Most do not
    /// include `session_id`; the only accepted exception is the transitional
    /// canonical envelope used for legacy `work_transitioned`.
    fn has_work_domain_payload_structure(
        event_type: &str,
        work_id: &str,
        payload: &[u8],
        _domain_prefix: &[u8],
    ) -> bool {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
            return false;
        };

        let work_id_field = value.get("work_id").and_then(|v| v.as_str());
        let session_id_field = value.get("session_id").and_then(|v| v.as_str());
        let has_session_id = session_id_field.is_some();
        let has_wrapped_payload = value.get("payload").and_then(|v| v.as_str()).is_some();
        let envelope_event_type = value.get("event_type").and_then(|v| v.as_str());

        if work_id_field != Some(work_id) {
            return false;
        }

        if !has_session_id {
            return true;
        }

        // Transitional canonical envelope for legacy `work_transitioned` event
        // type: allow only the exact envelope shape emitted by work-domain
        // handlers.
        event_type == "work_transitioned"
            && has_wrapped_payload
            && envelope_event_type == Some("work_transitioned")
            && session_id_field == Some(work_id)
    }

    fn status_from_work(
        projection: &WorkObjectProjection,
        work: &Work,
        evaluation_time_ns: u64,
    ) -> WorkAuthorityStatus {
        let dependency_evaluation =
            projection.evaluate_work_dependencies(&work.work_id, evaluation_time_ns);

        // STEP_10: Derive FAC identity chain status from projection
        // reducer state.
        //
        // MAJOR fix: check both digest match AND receipt outcome.
        // Digest match alone is insufficient — a receipt whose digest
        // matches the latest changeset but whose outcome is "failed"
        // must NOT report "passed".
        let latest_digest = projection.latest_changeset_digest(&work.work_id);
        let gate_status = latest_digest
            .and_then(|ld| {
                projection.ci_receipt_digest(&work.work_id).map(|ci| {
                    if ci == ld {
                        // Digest matches — check the outcome.
                        match projection.ci_receipt_outcome(&work.work_id) {
                            Some(apm2_core::work::ReceiptOutcome::Passed) => "passed".to_string(),
                            Some(apm2_core::work::ReceiptOutcome::Failed) => "failed".to_string(),
                            // No outcome recorded (should not happen if
                            // digest is present, but fail-closed to pending).
                            None => "pending".to_string(),
                        }
                    } else {
                        "pending".to_string()
                    }
                })
            })
            .or_else(|| latest_digest.map(|_| "pending".to_string()));
        let review_status = latest_digest
            .and_then(|ld| {
                projection.review_receipt_digest(&work.work_id).map(|rd| {
                    if rd == ld {
                        // Digest matches — check the outcome.
                        match projection.review_receipt_outcome(&work.work_id) {
                            Some(apm2_core::work::ReceiptOutcome::Passed) => "passed".to_string(),
                            Some(apm2_core::work::ReceiptOutcome::Failed) => "failed".to_string(),
                            None => "pending".to_string(),
                        }
                    } else {
                        "pending".to_string()
                    }
                })
            })
            .or_else(|| latest_digest.map(|_| "pending".to_string()));
        let merge_status = latest_digest
            .and_then(|ld| {
                projection.merge_receipt_digest(&work.work_id).map(|md| {
                    if md == ld {
                        "merged".to_string()
                    } else {
                        "pending".to_string()
                    }
                })
            })
            .or_else(|| latest_digest.map(|_| "pending".to_string()));

        // STEP_10: Populate identity chain surface fields from projection
        // reducer state rather than hardcoding None/0.
        let changeset_published_event_id = projection
            .changeset_published_event_id(&work.work_id)
            .map(ToString::to_string);
        let bundle_cas_hash = projection.bundle_cas_hash(&work.work_id);
        // MAJOR fix: Report per-work-item defect count (not global queue
        // length). Field 17 of `WorkStatusResponse` is documented as "for
        // this work item".
        let identity_chain_defect_count =
            projection.identity_chain_defect_count_for_work(&work.work_id);

        WorkAuthorityStatus {
            work_id: work.work_id.clone(),
            state: work.state,
            claimable: work.state.is_claimable(),
            created_at_ns: work.opened_at,
            last_transition_at_ns: work.last_transition_at,
            transition_count: work.transition_count,
            claimed_at_ns: work.claimed_at,
            implementer_claim_blocked: dependency_evaluation.implementer_claim_blocked,
            dependency_diagnostics: dependency_evaluation.diagnostics,
            latest_changeset_digest: latest_digest,
            changeset_published_event_id,
            bundle_cas_hash,
            gate_status,
            review_status,
            merge_status,
            identity_chain_defect_count,
        }
    }

    /// Clamps `limit` to `MAX_WORK_LIST_ROWS` and applies cursor-based
    /// pagination over a deterministically-ordered iterator.
    fn bounded_collect<'a, I>(
        projection: &WorkObjectProjection,
        iter: I,
        limit: usize,
        cursor: &str,
        evaluation_time_ns: u64,
    ) -> Vec<WorkAuthorityStatus>
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
            .map(|work| Self::status_from_work(projection, work, evaluation_time_ns))
            .collect();

        // Ensure deterministic ordering by work_id (BTreeMap already sorted).
        items.sort_by(|a, b| a.work_id.cmp(&b.work_id));
        items
    }

    /// Returns status for a single work item at the provided evaluation time.
    pub fn get_work_status_at_time(
        &self,
        work_id: &str,
        evaluation_time_ns: u64,
    ) -> Result<WorkAuthorityStatus, WorkAuthorityError> {
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

        Ok(Self::status_from_work(
            &projection,
            work,
            evaluation_time_ns,
        ))
    }

    /// Returns claimable work rows at the provided evaluation time.
    pub fn list_claimable_at_time(
        &self,
        limit: usize,
        cursor: &str,
        evaluation_time_ns: u64,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError> {
        self.refresh_projection()?;

        let projection =
            self.projection
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        Ok(Self::bounded_collect(
            &projection,
            projection.claimable_work().into_iter(),
            limit,
            cursor,
            evaluation_time_ns,
        ))
    }

    /// Returns all known work rows at the provided evaluation time.
    pub fn list_all_at_time(
        &self,
        limit: usize,
        cursor: &str,
        evaluation_time_ns: u64,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError> {
        self.refresh_projection()?;

        let projection =
            self.projection
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        Ok(Self::bounded_collect(
            &projection,
            projection.list_work().into_iter(),
            limit,
            cursor,
            evaluation_time_ns,
        ))
    }

    fn default_evaluation_time_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
            })
    }
}

impl WorkAuthority for ProjectionWorkAuthority {
    fn get_work_status(&self, work_id: &str) -> Result<WorkAuthorityStatus, WorkAuthorityError> {
        self.get_work_status_at_time(work_id, Self::default_evaluation_time_ns())
    }

    fn list_claimable(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError> {
        self.list_claimable_at_time(limit, cursor, Self::default_evaluation_time_ns())
    }

    fn list_all(
        &self,
        limit: usize,
        cursor: &str,
    ) -> Result<Vec<WorkAuthorityStatus>, WorkAuthorityError> {
        self.list_all_at_time(limit, cursor, Self::default_evaluation_time_ns())
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

/// Maximum number of work entries tracked in the in-memory ticket-alias index.
///
/// The index is bounded with deterministic eviction (oldest work ID first)
/// per RS-27 to prevent unbounded growth from ledger replay churn.
pub const MAX_TICKET_ALIAS_INDEX_WORK_ITEMS: usize = 2_048;

/// Maximum number of lossy alias markers retained after work-ID eviction.
///
/// When this cap is exceeded the index saturates and resolution fails closed
/// until the projection shrinks enough to clear lossy state.
pub const MAX_TICKET_ALIAS_INDEX_EVICTED_ALIASES: usize = MAX_TICKET_ALIAS_INDEX_WORK_ITEMS * 8;

/// Maximum number of resolved `spec_snapshot_hash -> ticket_alias` entries.
///
/// This cache prevents repeated CAS retrievals for work items that were
/// evicted from `spec_hash_by_work_id` due to bounded in-memory capacity.
pub const MAX_TICKET_ALIAS_INDEX_RESOLVED_SPEC_HASHES: usize =
    MAX_TICKET_ALIAS_INDEX_WORK_ITEMS * 8;

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

    /// Resolves a ticket alias to a canonical `work_id` via projection state.
    ///
    /// Returns `Ok(Some(work_id))` when the alias resolves to exactly one
    /// work item, `Ok(None)` when no match is found, or `Err` on
    /// infrastructure failure or ambiguous resolution (fail-closed).
    ///
    /// # TCK-00636: RFC-0032 Phase 1
    ///
    /// This method enables `--ticket-alias` -> `work_id` resolution via
    /// projections. The default implementation returns `Ok(None)` for
    /// backward compatibility; `ProjectionAliasReconciliationGate` overrides
    /// with CAS-backed `WorkSpec` lookup when a CAS store is configured.
    fn resolve_ticket_alias(
        &self,
        _ticket_alias: &str,
    ) -> Result<Option<String>, WorkAuthorityError> {
        Ok(None)
    }
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

    /// Optional CAS store for resolving `WorkSpecV1` documents by
    /// `spec_snapshot_hash`. When set, enables CAS-backed ticket alias
    /// resolution (TCK-00636, RFC-0032 Phase 1).
    cas: Option<Arc<dyn apm2_core::evidence::ContentAddressedStore>>,

    /// Bounded in-memory index for `ticket_alias -> work_id` lookups.
    ///
    /// Synchronization protocol:
    /// 1. Writers: only `refresh_projection()` mutates index contents while
    ///    holding the projection write lock and then this index write lock.
    /// 2. Readers: `build_canonical_projections()` and `resolve_ticket_alias()`
    ///    take read locks only.
    /// 3. No async suspension occurs while guards are held.
    ticket_alias_index: Arc<RwLock<TicketAliasIndex>>,
}

#[derive(Debug, Default)]
struct TicketAliasIndex {
    alias_to_work_ids: HashMap<String, BTreeSet<String>>,
    work_id_to_alias: HashMap<String, String>,
    spec_hash_by_work_id: HashMap<String, [u8; 32]>,
    // Eviction sort key by work_id: (created_at_ns, first_seen_sequence).
    // Lower keys are evicted first when capacity is exceeded.
    work_sort_keys: HashMap<String, (u64, u64)>,
    work_ids_by_sort_key: BTreeSet<(u64, u64, String)>,
    next_work_sort_seq: u64,
    resolved_alias_by_spec_hash: HashMap<[u8; 32], Option<String>>,
    resolved_spec_hash_order: VecDeque<[u8; 32]>,
    evicted_aliases: HashSet<String>,
    evicted_aliases_saturated: bool,
}

impl TicketAliasIndex {
    fn clear(&mut self) {
        self.alias_to_work_ids.clear();
        self.work_id_to_alias.clear();
        self.spec_hash_by_work_id.clear();
        self.work_sort_keys.clear();
        self.work_ids_by_sort_key.clear();
        self.next_work_sort_seq = 0;
        self.resolved_alias_by_spec_hash.clear();
        self.resolved_spec_hash_order.clear();
        self.evicted_aliases.clear();
        self.evicted_aliases_saturated = false;
    }

    fn remove_work(
        &mut self,
        work_id: &str,
        mark_alias_evicted: bool,
    ) -> Result<(), WorkAuthorityError> {
        self.spec_hash_by_work_id.remove(work_id);
        if let Some((created_at_ns, sequence)) = self.work_sort_keys.remove(work_id) {
            self.work_ids_by_sort_key
                .remove(&(created_at_ns, sequence, work_id.to_string()));
        }

        if let Some(alias) = self.work_id_to_alias.remove(work_id) {
            if let Some(work_ids) = self.alias_to_work_ids.get_mut(&alias) {
                work_ids.remove(work_id);
                if work_ids.is_empty() {
                    self.alias_to_work_ids.remove(&alias);
                }
            }
            if mark_alias_evicted {
                self.mark_alias_evicted(alias)?;
            }
        }
        Ok(())
    }

    fn upsert_work_sort_key(&mut self, work_id: &str, created_at_ns: u64, sequence: u64) {
        if let Some((previous_created_at_ns, previous_sequence)) = self
            .work_sort_keys
            .insert(work_id.to_string(), (created_at_ns, sequence))
        {
            self.work_ids_by_sort_key.remove(&(
                previous_created_at_ns,
                previous_sequence,
                work_id.to_string(),
            ));
        }
        self.work_ids_by_sort_key
            .insert((created_at_ns, sequence, work_id.to_string()));
    }

    fn mark_alias_evicted(&mut self, alias: String) -> Result<(), WorkAuthorityError> {
        if self.evicted_aliases.contains(&alias) {
            return Ok(());
        }

        if self.evicted_aliases.len() >= MAX_TICKET_ALIAS_INDEX_EVICTED_ALIASES {
            self.evicted_aliases_saturated = true;
            return Err(WorkAuthorityError::ProjectionLock {
                message: format!(
                    "ticket alias index lossy marker capacity exceeded: {} (max \
                     {MAX_TICKET_ALIAS_INDEX_EVICTED_ALIASES}); refusing lossy resolution",
                    self.evicted_aliases.len() + 1
                ),
            });
        }

        self.evicted_aliases.insert(alias);
        Ok(())
    }

    fn upsert_spec_hash(&mut self, work_id: &str, spec_hash: [u8; 32], created_at_ns: u64) -> bool {
        if self.spec_hash_by_work_id.get(work_id) == Some(&spec_hash) {
            if !self.work_sort_keys.contains_key(work_id) {
                let sequence = self.next_work_sort_seq;
                self.upsert_work_sort_key(work_id, created_at_ns, sequence);
                self.next_work_sort_seq = self.next_work_sort_seq.saturating_add(1);
            }
            return false;
        }

        let work_id_key = work_id.to_string();
        let is_new = self
            .spec_hash_by_work_id
            .insert(work_id_key.clone(), spec_hash)
            .is_none();
        if is_new {
            let sequence = self.next_work_sort_seq;
            self.upsert_work_sort_key(&work_id_key, created_at_ns, sequence);
            self.next_work_sort_seq = self.next_work_sort_seq.saturating_add(1);
        } else if let Some((_, sequence)) = self.work_sort_keys.get(work_id).copied() {
            self.upsert_work_sort_key(work_id, created_at_ns, sequence);
        } else {
            let sequence = self.next_work_sort_seq;
            self.upsert_work_sort_key(work_id, created_at_ns, sequence);
            self.next_work_sort_seq = self.next_work_sort_seq.saturating_add(1);
        }
        true
    }

    fn upsert_alias(&mut self, work_id: &str, alias: Option<String>) {
        if let Some(previous_alias) = self.work_id_to_alias.remove(work_id) {
            if let Some(work_ids) = self.alias_to_work_ids.get_mut(&previous_alias) {
                work_ids.remove(work_id);
                if work_ids.is_empty() {
                    self.alias_to_work_ids.remove(&previous_alias);
                }
            }
        }

        if let Some(alias) = alias {
            self.alias_to_work_ids
                .entry(alias.clone())
                .or_default()
                .insert(work_id.to_string());
            self.work_id_to_alias.insert(work_id.to_string(), alias);
        }
    }

    fn resolved_alias_for_spec_hash(&self, spec_hash: &[u8; 32]) -> (bool, Option<String>) {
        self.resolved_alias_by_spec_hash
            .get(spec_hash)
            .map_or((false, None), |alias| (true, alias.clone()))
    }

    fn cache_resolved_alias(&mut self, spec_hash: [u8; 32], alias: Option<String>) {
        if self.resolved_alias_by_spec_hash.contains_key(&spec_hash) {
            return;
        }

        self.resolved_alias_by_spec_hash.insert(spec_hash, alias);
        self.resolved_spec_hash_order.push_back(spec_hash);

        while self.resolved_alias_by_spec_hash.len() > MAX_TICKET_ALIAS_INDEX_RESOLVED_SPEC_HASHES {
            let Some(oldest_hash) = self.resolved_spec_hash_order.pop_front() else {
                break;
            };
            self.resolved_alias_by_spec_hash.remove(&oldest_hash);
        }
    }

    fn enforce_capacity(&mut self) -> Result<(), WorkAuthorityError> {
        while self.spec_hash_by_work_id.len() > MAX_TICKET_ALIAS_INDEX_WORK_ITEMS {
            let Some((_, _, oldest_work_id)) = self.work_ids_by_sort_key.iter().next().cloned()
            else {
                break;
            };
            let evicted_created_at_ns = self
                .work_sort_keys
                .get(&oldest_work_id)
                .map_or(0, |(created_at_ns, _)| *created_at_ns);
            self.remove_work(&oldest_work_id, true)?;
            warn!(
                work_id = %oldest_work_id,
                created_at_ns = evicted_created_at_ns,
                max_entries = MAX_TICKET_ALIAS_INDEX_WORK_ITEMS,
                "ticket alias index reached capacity; evicted oldest work binding by created_at_ns"
            );
        }
        Ok(())
    }
}

impl ProjectionAliasReconciliationGate {
    /// Creates a new alias reconciliation gate using an existing projection.
    ///
    /// This allows the dispatcher to share projection state with
    /// [`ProjectionWorkAuthority`] instead of maintaining a parallel
    /// `WorkObjectProjection` for the same event emitter.
    #[must_use]
    pub(crate) fn new_with_projection(
        event_emitter: Arc<dyn LedgerEventEmitter>,
        projection: Arc<RwLock<WorkObjectProjection>>,
    ) -> Self {
        Self {
            projection,
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
            cas: None,
            ticket_alias_index: Arc::new(RwLock::new(TicketAliasIndex::default())),
        }
    }

    /// Creates a new alias reconciliation gate backed by the given emitter.
    ///
    /// Uses default observation window and sunset criteria.
    #[must_use]
    pub fn new(event_emitter: Arc<dyn LedgerEventEmitter>) -> Self {
        Self::new_with_projection(
            event_emitter,
            Arc::new(RwLock::new(WorkObjectProjection::new())),
        )
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
            cas: None,
            ticket_alias_index: Arc::new(RwLock::new(TicketAliasIndex::default())),
        }
    }

    /// Sets the CAS store for resolving `WorkSpecV1` documents.
    ///
    /// When set, enables CAS-backed ticket alias resolution via
    /// [`AliasReconciliationGate::resolve_ticket_alias`].
    #[must_use]
    pub fn with_cas(mut self, cas: Arc<dyn apm2_core::evidence::ContentAddressedStore>) -> Self {
        self.cas = Some(cas);
        if let Ok(mut alias_index) = self.ticket_alias_index.write() {
            alias_index.clear();
        }
        self
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
        let last_refreshed_event_count = {
            let cached =
                self.last_event_count
                    .read()
                    .map_err(|err| WorkAuthorityError::ProjectionLock {
                        message: err.to_string(),
                    })?;
            if *cached == current_count {
                return Ok(());
            }
            *cached
        };

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
                if let Some(cas) = self.cas.as_ref() {
                    self.refresh_ticket_alias_index(
                        &projection,
                        cas.as_ref(),
                        &signed_events,
                        last_refreshed_event_count,
                    )?;
                } else {
                    let mut alias_index = self.ticket_alias_index.write().map_err(|err| {
                        WorkAuthorityError::ProjectionLock {
                            message: err.to_string(),
                        }
                    })?;
                    alias_index.clear();
                }

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

    fn refresh_ticket_alias_index(
        &self,
        projection: &WorkObjectProjection,
        cas: &dyn apm2_core::evidence::ContentAddressedStore,
        signed_events: &[SignedLedgerEvent],
        last_refreshed_event_count: usize,
    ) -> Result<(), WorkAuthorityError> {
        let mut alias_index =
            self.ticket_alias_index
                .write()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        // Clear lossy markers once the projection can fully fit in-memory.
        if projection.work_count() <= MAX_TICKET_ALIAS_INDEX_WORK_ITEMS {
            alias_index.evicted_aliases.clear();
            alias_index.evicted_aliases_saturated = false;
        } else if alias_index.evicted_aliases_saturated {
            return Err(WorkAuthorityError::ProjectionLock {
                message: format!(
                    "ticket alias index lossy marker capacity saturated (max \
                     {MAX_TICKET_ALIAS_INDEX_EVICTED_ALIASES}); refusing lossy resolution"
                ),
            });
        }

        // Drop entries for work IDs no longer present in projection.
        let tracked_work_ids: Vec<String> =
            alias_index.spec_hash_by_work_id.keys().cloned().collect();
        for work_id in tracked_work_ids {
            if projection.get_work(&work_id).is_none() {
                alias_index.remove_work(&work_id, false)?;
            }
        }

        let mut work_ids_to_refresh = BTreeSet::new();
        if last_refreshed_event_count <= signed_events.len() {
            for event in &signed_events[last_refreshed_event_count..] {
                if !event.work_id.is_empty() {
                    work_ids_to_refresh.insert(event.work_id.clone());
                }
            }
        } else {
            warn!(
                last_refreshed_event_count,
                current_event_count = signed_events.len(),
                "ticket alias index: event stream length regressed; falling back to full work scan"
            );
            for work in projection.iter_work() {
                work_ids_to_refresh.insert(work.work_id.clone());
            }
        }

        // Also rescan any projection work whose current spec hash has no
        // resolved cache entry yet (or has changed since the last resolve)
        // so transient CAS failures are retried even without a matching
        // event in the latest delta window.
        for work in projection.iter_work() {
            let Ok(projected_spec_hash) = Self::extract_spec_snapshot_hash(work) else {
                work_ids_to_refresh.insert(work.work_id.clone());
                continue;
            };
            let cached_spec_hash = alias_index.spec_hash_by_work_id.get(&work.work_id).copied();
            if cached_spec_hash != projected_spec_hash {
                work_ids_to_refresh.insert(work.work_id.clone());
            }
        }

        if work_ids_to_refresh.is_empty() {
            return Ok(());
        }

        // Incrementally process work IDs touched by event deltas plus any
        // entries with missing/stale spec-hash cache state.
        for work_id in work_ids_to_refresh {
            let Some(work) = projection.get_work(&work_id) else {
                alias_index.remove_work(&work_id, false)?;
                continue;
            };

            let spec_hash = match Self::extract_spec_snapshot_hash(work) {
                Ok(spec_hash) => spec_hash,
                Err(error) => {
                    warn!(
                        work_id = %work.work_id,
                        error = %error,
                        "ticket alias index: invalid spec_snapshot_hash; removing stale alias mapping"
                    );
                    alias_index.remove_work(&work.work_id, false)?;
                    continue;
                },
            };

            let Some(spec_hash) = spec_hash else {
                alias_index.remove_work(&work.work_id, false)?;
                continue;
            };

            if alias_index.spec_hash_by_work_id.get(&work.work_id) == Some(&spec_hash) {
                continue;
            }

            let (has_cached_alias, cached_alias) =
                alias_index.resolved_alias_for_spec_hash(&spec_hash);
            let ticket_alias = if has_cached_alias {
                cached_alias
            } else {
                match Self::resolve_ticket_alias_from_spec_hash(cas, &work.work_id, spec_hash) {
                    Ok(alias) => {
                        alias_index.cache_resolved_alias(spec_hash, alias.clone());
                        alias
                    },
                    Err(error) => {
                        warn!(
                            work_id = %work.work_id,
                            error = %error,
                            "ticket alias index: CAS/WorkSpec decode failed; removing alias mapping"
                        );
                        alias_index.remove_work(&work.work_id, false)?;
                        continue;
                    },
                }
            };

            // Record the spec hash only after alias extraction succeeds so
            // transient CAS failures can retry on future projection refreshes.
            alias_index.upsert_spec_hash(&work.work_id, spec_hash, work.opened_at);
            alias_index.upsert_alias(&work.work_id, ticket_alias);
            alias_index.enforce_capacity()?;
        }

        Ok(())
    }

    fn extract_spec_snapshot_hash(work: &Work) -> Result<Option<[u8; 32]>, WorkAuthorityError> {
        if work.spec_snapshot_hash.is_empty() {
            return Ok(None);
        }

        work.spec_snapshot_hash
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|_| WorkAuthorityError::ProjectionLock {
                message: format!("spec_snapshot_hash for {} is not 32 bytes", work.work_id),
            })
    }

    fn resolve_ticket_alias_from_spec_hash(
        cas: &dyn apm2_core::evidence::ContentAddressedStore,
        work_id: &str,
        spec_hash: [u8; 32],
    ) -> Result<Option<String>, WorkAuthorityError> {
        let spec_bytes =
            cas.retrieve(&spec_hash)
                .map_err(|e| WorkAuthorityError::ProjectionLock {
                    message: format!("CAS retrieval failed for work_id={work_id}: {e}"),
                })?;
        let work_spec = apm2_core::fac::work_cas_schemas::bounded_decode_work_spec(&spec_bytes)
            .map_err(|e| WorkAuthorityError::ProjectionLock {
                message: format!("WorkSpec decode failed for work_id={work_id}: {e}"),
            })?;
        Ok(work_spec.ticket_alias)
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
        for work in projection.iter_work() {
            // The work_id itself is the canonical identity. We use a SHA-256
            // hash of the work_id string as the alias_reconcile::Hash.
            let hash = work_id_to_hash(&work.work_id);
            projections
                .entry(work.work_id.clone())
                .or_default()
                .push(hash);
        }

        if self.cas.is_some() {
            let alias_index = self.ticket_alias_index.read().map_err(|err| {
                WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                }
            })?;

            if alias_index.evicted_aliases_saturated {
                return Err(WorkAuthorityError::ProjectionLock {
                    message: format!(
                        "ticket alias index lossy marker capacity saturated (max \
                         {MAX_TICKET_ALIAS_INDEX_EVICTED_ALIASES}); refusing lossy canonical \
                         projections"
                    ),
                });
            }

            for (alias, work_ids) in &alias_index.alias_to_work_ids {
                // Evicted aliases are considered lossy and omitted so
                // reconciliation remains fail-closed (missing alias -> defect).
                if alias_index.evicted_aliases.contains(alias) {
                    continue;
                }

                let entry = projections.entry(alias.clone()).or_default();
                for work_id in work_ids {
                    entry.push(work_id_to_hash(work_id));
                }
            }
        }

        for hashes in projections.values_mut() {
            hashes.sort_unstable();
            hashes.dedup();
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

    /// Resolves a ticket alias to a canonical `work_id` using the in-memory
    /// alias index maintained during projection refresh (TCK-00636, RFC-0032
    /// Phase 1).
    ///
    /// # Fail-closed semantics
    ///
    /// - No CAS store configured: returns `Ok(None)` (feature not wired)
    /// - CAS miss/malformed `WorkSpec` during index refresh: item omitted
    /// - Alias evicted from bounded index: returns `Err` (lossy -> deny)
    /// - Ambiguous (multiple matches): returns `Err` (fail-closed)
    fn resolve_ticket_alias(
        &self,
        ticket_alias: &str,
    ) -> Result<Option<String>, WorkAuthorityError> {
        if self.cas.is_none() {
            return Ok(None);
        }

        self.refresh_projection()?;

        let alias_index =
            self.ticket_alias_index
                .read()
                .map_err(|err| WorkAuthorityError::ProjectionLock {
                    message: err.to_string(),
                })?;

        if alias_index.evicted_aliases_saturated {
            return Err(WorkAuthorityError::ProjectionLock {
                message: format!(
                    "ticket alias index lossy marker capacity saturated (max \
                     {MAX_TICKET_ALIAS_INDEX_EVICTED_ALIASES}); refusing lossy resolution"
                ),
            });
        }

        if alias_index.evicted_aliases.contains(ticket_alias) {
            return Err(WorkAuthorityError::ProjectionLock {
                message: format!(
                    "ticket alias '{ticket_alias}' was evicted from bounded index (max \
                     {MAX_TICKET_ALIAS_INDEX_WORK_ITEMS} work items); refusing lossy resolution"
                ),
            });
        }

        let Some(work_ids) = alias_index.alias_to_work_ids.get(ticket_alias) else {
            return Ok(None);
        };
        let matches: Vec<String> = work_ids.iter().cloned().collect();

        match matches.as_slice() {
            [] => Ok(None),
            [work_id] => Ok(Some(work_id.clone())),
            _ => {
                warn!(
                    ticket_alias = %ticket_alias,
                    match_count = matches.len(),
                    work_ids = ?matches,
                    "Ambiguous ticket alias resolution (fail-closed)"
                );
                Err(WorkAuthorityError::ProjectionLock {
                    message: format!(
                        "ambiguous ticket alias '{ticket_alias}' resolves to {} work items: \
                         {matches:?} (fail-closed: alias reconciliation requires unique resolution)",
                        matches.len()
                    ),
                })
            },
        }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use apm2_core::events::{WorkEdgeAdded, WorkEdgeType};
    use apm2_core::evidence::{CasError, ContentAddressedStore, StoreResult};
    use prost::Message;

    use super::*;

    fn signed_event(event_type: &str, payload: Vec<u8>) -> SignedLedgerEvent {
        SignedLedgerEvent {
            event_id: format!("EVT-{event_type}"),
            event_type: event_type.to_string(),
            work_id: "W-test-001".to_string(),
            actor_id: "actor:test".to_string(),
            payload,
            signature: vec![0u8; 64],
            timestamp_ns: 1_000_000_000,
        }
    }

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

    #[test]
    fn filter_rejects_session_wrapped_work_graph_events() {
        let mut edge_payload = Vec::new();
        WorkEdgeAdded {
            from_work_id: "W-pre-001".to_string(),
            to_work_id: "W-target-001".to_string(),
            edge_type: WorkEdgeType::Blocks as i32,
            rationale: "test".to_string(),
        }
        .encode(&mut edge_payload)
        .expect("WorkEdgeAdded payload should encode");

        let wrapped_payload = serde_json::to_vec(&serde_json::json!({
            "event_type": "work_graph.edge.added",
            "session_id": "S-test-001",
            "actor_id": "S-test-001",
            "payload": hex::encode(&edge_payload),
        }))
        .expect("session wrapper should encode");

        let events = vec![
            signed_event("work_graph.edge.added", wrapped_payload),
            signed_event("work_graph.edge.added", edge_payload),
        ];
        let filtered = ProjectionWorkAuthority::filter_work_domain_events(&events);

        assert_eq!(
            filtered.len(),
            1,
            "session-wrapped work_graph edge events must be rejected"
        );
    }

    #[test]
    fn filter_rejects_session_wrapped_work_graph_typed_alias() {
        let wrapped_payload = serde_json::to_vec(&serde_json::json!({
            "event_type": "WorkEdgeAdded",
            "session_id": "S-test-002",
            "actor_id": "S-test-002",
            "payload": "deadbeef",
        }))
        .expect("session wrapper should encode");

        let events = vec![signed_event("WorkEdgeAdded", wrapped_payload)];
        let filtered = ProjectionWorkAuthority::filter_work_domain_events(&events);

        assert!(
            filtered.is_empty(),
            "typed work graph aliases must reject session wrappers"
        );
    }

    #[test]
    fn filter_allows_direct_json_work_graph_payload() {
        let waiver_payload = serde_json::to_vec(&serde_json::json!({
            "from_work_id": "W-pre-003",
            "to_work_id": "W-target-003",
            "original_edge_type": "BLOCKS",
            "waiver_id": "WVR-003",
            "expires_at_ns": 12345,
        }))
        .expect("waiver payload should encode");

        let events = vec![signed_event("work_graph.edge.waived", waiver_payload)];
        let filtered = ProjectionWorkAuthority::filter_work_domain_events(&events);

        assert_eq!(
            filtered.len(),
            1,
            "direct JSON work_graph payloads without session wrapper must be accepted"
        );
    }

    // ====================================================================
    // TCK-00636: Ticket Alias Resolution Tests (RFC-0032 Phase 1)
    // ====================================================================

    /// Creates a `MemoryCas` with a `WorkSpecV1` stored under `spec_hash`,
    /// returning `(cas, spec_hash)`.
    fn setup_cas_with_work_spec(
        work_id: &str,
        ticket_alias: Option<&str>,
    ) -> (Arc<apm2_core::evidence::MemoryCas>, [u8; 32]) {
        use apm2_core::evidence::MemoryCas;
        use apm2_core::fac::work_cas_schemas::{
            WORK_SPEC_V1_SCHEMA, WorkSpecType, WorkSpecV1, canonicalize_for_cas,
        };

        let cas = Arc::new(MemoryCas::new());
        let spec = WorkSpecV1 {
            schema: WORK_SPEC_V1_SCHEMA.to_string(),
            work_id: work_id.to_string(),
            ticket_alias: ticket_alias.map(str::to_string),
            title: format!("Test work {work_id}"),
            summary: None,
            work_type: WorkSpecType::Ticket,
            repo: None,
            requirement_ids: Vec::new(),
            labels: Vec::new(),
            rfc_id: None,
            parent_work_ids: Vec::new(),
            created_at_ns: Some(1_000_000_000),
        };
        let spec_json = serde_json::to_string(&spec).expect("spec serializes");
        let canonical = canonicalize_for_cas(&spec_json).expect("canonical JSON");
        let stored = cas.store(canonical.as_bytes()).expect("CAS store");
        (cas, stored.hash)
    }

    #[derive(Debug, Default)]
    struct CountingCas {
        inner: apm2_core::evidence::MemoryCas,
        retrieve_count: AtomicUsize,
    }

    impl CountingCas {
        fn new() -> Self {
            Self {
                inner: apm2_core::evidence::MemoryCas::new(),
                retrieve_count: AtomicUsize::new(0),
            }
        }

        fn retrieve_count(&self) -> usize {
            self.retrieve_count.load(Ordering::SeqCst)
        }
    }

    impl ContentAddressedStore for CountingCas {
        fn store(&self, content: &[u8]) -> Result<StoreResult, CasError> {
            self.inner.store(content)
        }

        fn retrieve(&self, hash: &[u8; 32]) -> Result<Vec<u8>, CasError> {
            self.retrieve_count.fetch_add(1, Ordering::SeqCst);
            self.inner.retrieve(hash)
        }

        fn exists(&self, hash: &[u8; 32]) -> Result<bool, CasError> {
            self.inner.exists(hash)
        }

        fn size(&self, hash: &[u8; 32]) -> Result<usize, CasError> {
            self.inner.size(hash)
        }
    }

    #[derive(Debug)]
    struct FlakyCas {
        inner: apm2_core::evidence::MemoryCas,
        transient_failures_remaining: AtomicUsize,
    }

    impl FlakyCas {
        fn new(transient_failures: usize) -> Self {
            Self {
                inner: apm2_core::evidence::MemoryCas::new(),
                transient_failures_remaining: AtomicUsize::new(transient_failures),
            }
        }
    }

    impl ContentAddressedStore for FlakyCas {
        fn store(&self, content: &[u8]) -> Result<StoreResult, CasError> {
            self.inner.store(content)
        }

        fn retrieve(&self, hash: &[u8; 32]) -> Result<Vec<u8>, CasError> {
            if self
                .transient_failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    if remaining > 0 {
                        Some(remaining - 1)
                    } else {
                        None
                    }
                })
                .is_ok()
            {
                return Err(CasError::StorageError {
                    message: "injected transient retrieve failure".to_string(),
                });
            }
            self.inner.retrieve(hash)
        }

        fn exists(&self, hash: &[u8; 32]) -> Result<bool, CasError> {
            self.inner.exists(hash)
        }

        fn size(&self, hash: &[u8; 32]) -> Result<usize, CasError> {
            self.inner.size(hash)
        }
    }

    fn store_work_spec_in_cas(
        cas: &dyn ContentAddressedStore,
        work_id: &str,
        ticket_alias: Option<&str>,
        created_at_ns: u64,
    ) -> [u8; 32] {
        use apm2_core::fac::work_cas_schemas::{
            WORK_SPEC_V1_SCHEMA, WorkSpecType, WorkSpecV1, canonicalize_for_cas,
        };

        let spec = WorkSpecV1 {
            schema: WORK_SPEC_V1_SCHEMA.to_string(),
            work_id: work_id.to_string(),
            ticket_alias: ticket_alias.map(str::to_string),
            title: format!("Test work {work_id}"),
            summary: None,
            work_type: WorkSpecType::Ticket,
            repo: None,
            requirement_ids: Vec::new(),
            labels: Vec::new(),
            rfc_id: None,
            parent_work_ids: Vec::new(),
            created_at_ns: Some(created_at_ns),
        };
        let spec_json = serde_json::to_string(&spec).expect("spec serializes");
        let canonical = canonicalize_for_cas(&spec_json).expect("canonical JSON");
        cas.store(canonical.as_bytes())
            .expect("CAS store should succeed")
            .hash
    }

    fn setup_counting_cas_with_work_spec(
        work_id: &str,
        ticket_alias: Option<&str>,
    ) -> (Arc<CountingCas>, [u8; 32]) {
        let cas = Arc::new(CountingCas::new());
        let spec_hash = store_work_spec_in_cas(cas.as_ref(), work_id, ticket_alias, 1_000_000_000);
        (cas, spec_hash)
    }

    fn make_work_opened_session_envelope_payload(work_id: &str, spec_hash: Vec<u8>) -> Vec<u8> {
        use apm2_core::work::helpers::work_opened_payload;

        let opened_payload = work_opened_payload(work_id, "TICKET", spec_hash, vec![], vec![]);
        serde_json::to_vec(&serde_json::json!({
            "event_type": "work.opened",
            "session_id": work_id,
            "actor_id": "actor:test",
            "payload": hex::encode(opened_payload),
        }))
        .expect("work.opened session envelope should encode")
    }

    /// Builds a minimal `LedgerEventEmitter` that emits `work.opened` events
    /// via the `StubLedgerEventEmitter` with `inject_raw_event`.
    fn make_emitter_with_work(work_ids: &[(&str, Vec<u8>)]) -> Arc<dyn LedgerEventEmitter> {
        let emitter = crate::protocol::dispatch::StubLedgerEventEmitter::new();
        for (idx, (work_id, spec_hash)) in work_ids.iter().enumerate() {
            let event = SignedLedgerEvent {
                event_id: format!("EVT-opened-{idx}"),
                event_type: "work.opened".to_string(),
                work_id: work_id.to_string(),
                actor_id: "actor:test".to_string(),
                payload: make_work_opened_session_envelope_payload(work_id, spec_hash.clone()),
                signature: vec![0u8; 64],
                timestamp_ns: (idx as u64 + 1) * 1_000_000_000,
            };
            emitter.inject_raw_event(event);
        }
        Arc::new(emitter)
    }

    #[test]
    fn resolve_ticket_alias_returns_stable_work_id() {
        let (cas, spec_hash) = setup_cas_with_work_spec("W-636-001", Some("TCK-00636"));

        let emitter = make_emitter_with_work(&[("W-636-001", spec_hash.to_vec())]);

        let gate = ProjectionAliasReconciliationGate::new(emitter)
            .with_cas(cas as Arc<dyn apm2_core::evidence::ContentAddressedStore>);

        let result = gate.resolve_ticket_alias("TCK-00636");
        assert_eq!(
            result.expect("should not error"),
            Some("W-636-001".to_string()),
            "ticket alias must resolve to the canonical work_id"
        );

        // Deterministic: calling again returns the same result
        let result2 = gate.resolve_ticket_alias("TCK-00636");
        assert_eq!(
            result2.expect("should not error"),
            Some("W-636-001".to_string()),
            "alias resolution must be deterministic and replayable"
        );
    }

    #[test]
    fn resolve_ticket_alias_uses_index_without_repeated_cas_reads() {
        let (cas, spec_hash) = setup_counting_cas_with_work_spec("W-636-INDEX-001", Some("TCK-IX"));
        let emitter = make_emitter_with_work(&[("W-636-INDEX-001", spec_hash.to_vec())]);

        let gate = ProjectionAliasReconciliationGate::new(emitter)
            .with_cas(cas.clone() as Arc<dyn ContentAddressedStore>);

        let first = gate
            .resolve_ticket_alias("TCK-IX")
            .expect("first lookup should succeed");
        assert_eq!(first, Some("W-636-INDEX-001".to_string()));

        let retrieves_after_first = cas.retrieve_count();
        assert!(
            retrieves_after_first >= 1,
            "initial lookup should populate index from CAS at least once"
        );

        let second = gate
            .resolve_ticket_alias("TCK-IX")
            .expect("second lookup should succeed");
        assert_eq!(second, Some("W-636-INDEX-001".to_string()));
        assert_eq!(
            cas.retrieve_count(),
            retrieves_after_first,
            "repeated lookup on unchanged projection must not hit CAS again"
        );
    }

    #[test]
    fn resolve_ticket_alias_returns_none_for_unknown() {
        let (cas, spec_hash) = setup_cas_with_work_spec("W-636-002", Some("TCK-00999"));

        let emitter = make_emitter_with_work(&[("W-636-002", spec_hash.to_vec())]);

        let gate = ProjectionAliasReconciliationGate::new(emitter)
            .with_cas(cas as Arc<dyn apm2_core::evidence::ContentAddressedStore>);

        let result = gate.resolve_ticket_alias("TCK-00636");
        assert_eq!(
            result.expect("should not error"),
            None,
            "unknown ticket alias must return None"
        );
    }

    #[test]
    fn resolve_ticket_alias_returns_none_without_cas() {
        let emitter = make_emitter_with_work(&[("W-636-003", vec![0xAA; 32])]);

        let gate = ProjectionAliasReconciliationGate::new(emitter);
        // No CAS configured -- should return None, not error
        let result = gate.resolve_ticket_alias("TCK-00636");
        assert_eq!(
            result.expect("should not error"),
            None,
            "without CAS, alias resolution must return None (feature not wired)"
        );
    }

    #[test]
    fn resolve_ticket_alias_fails_on_ambiguity() {
        use apm2_core::fac::work_cas_schemas::{
            WORK_SPEC_V1_SCHEMA, WorkSpecType, WorkSpecV1, canonicalize_for_cas,
        };

        // Two work items both claim the same ticket alias
        let (cas1, hash1) = setup_cas_with_work_spec("W-636-004", Some("TCK-AMBIG"));
        let spec2 = WorkSpecV1 {
            schema: WORK_SPEC_V1_SCHEMA.to_string(),
            work_id: "W-636-005".to_string(),
            ticket_alias: Some("TCK-AMBIG".to_string()),
            title: "Ambiguous 2".to_string(),
            summary: None,
            work_type: WorkSpecType::Ticket,
            repo: None,
            requirement_ids: Vec::new(),
            labels: Vec::new(),
            rfc_id: None,
            parent_work_ids: Vec::new(),
            created_at_ns: Some(2_000_000_000),
        };
        let spec_json2 = serde_json::to_string(&spec2).expect("spec serializes");
        let canonical2 = canonicalize_for_cas(&spec_json2).expect("canonical JSON");
        let stored2 = cas1.store(canonical2.as_bytes()).expect("CAS store");

        let emitter = make_emitter_with_work(&[
            ("W-636-004", hash1.to_vec()),
            ("W-636-005", stored2.hash.to_vec()),
        ]);

        let gate = ProjectionAliasReconciliationGate::new(emitter)
            .with_cas(cas1 as Arc<dyn apm2_core::evidence::ContentAddressedStore>);

        let result = gate.resolve_ticket_alias("TCK-AMBIG");
        assert!(
            result.is_err(),
            "ambiguous ticket alias resolution must be fail-closed"
        );
    }

    #[test]
    fn resolve_ticket_alias_fails_closed_for_evicted_alias_entries() {
        let cas = Arc::new(apm2_core::evidence::MemoryCas::new());
        let gate = ProjectionAliasReconciliationGate::new(make_emitter_with_work(&[]))
            .with_cas(cas as Arc<dyn ContentAddressedStore>);

        {
            let mut alias_index = gate
                .ticket_alias_index
                .write()
                .expect("alias index lock should be available");
            alias_index
                .alias_to_work_ids
                .entry("TCK-EVICTED".to_string())
                .or_default()
                .insert("W-636-LOSSY-001".to_string());
            alias_index
                .evicted_aliases
                .insert("TCK-EVICTED".to_string());
        }

        let result = gate.resolve_ticket_alias("TCK-EVICTED");
        assert!(
            result.is_err(),
            "aliases marked lossy by bounded-index eviction must fail closed"
        );
    }

    #[test]
    fn ticket_alias_index_enforces_capacity_with_oldest_eviction() {
        let mut alias_index = TicketAliasIndex::default();

        for i in 0..=MAX_TICKET_ALIAS_INDEX_WORK_ITEMS {
            let work_id = format!("W-636-CAP-{i}");
            let alias = format!("TCK-CAP-{i}");
            let spec_hash = work_id_to_hash(&work_id);
            alias_index.upsert_spec_hash(&work_id, spec_hash, i as u64 + 1);
            alias_index.upsert_alias(&work_id, Some(alias));
            alias_index
                .enforce_capacity()
                .expect("capacity enforcement should not fail");
        }

        assert_eq!(
            alias_index.spec_hash_by_work_id.len(),
            MAX_TICKET_ALIAS_INDEX_WORK_ITEMS,
            "index must remain capped after insertion beyond capacity"
        );
        assert!(
            alias_index.evicted_aliases.contains("TCK-CAP-0"),
            "oldest alias must be marked lossy after eviction"
        );
    }

    #[test]
    fn ticket_alias_index_eviction_prefers_oldest_created_at() {
        let mut alias_index = TicketAliasIndex::default();

        for i in 0..MAX_TICKET_ALIAS_INDEX_WORK_ITEMS {
            let work_id = format!("W-636-TS-{i:04}");
            let alias = format!("TCK-636-TS-{i:04}");
            let spec_hash = work_id_to_hash(&work_id);
            alias_index.upsert_spec_hash(&work_id, spec_hash, 10_000 + i as u64);
            alias_index.upsert_alias(&work_id, Some(alias));
        }

        let oldest_work_id = "W-636-TS-OLDEST";
        let oldest_alias = "TCK-636-TS-OLDEST";
        alias_index.upsert_spec_hash(oldest_work_id, work_id_to_hash(oldest_work_id), 1);
        alias_index.upsert_alias(oldest_work_id, Some(oldest_alias.to_string()));
        alias_index
            .enforce_capacity()
            .expect("capacity enforcement should not fail");

        assert!(
            !alias_index
                .spec_hash_by_work_id
                .contains_key(oldest_work_id),
            "capacity eviction must target the oldest created_at_ns even when inserted last"
        );
        assert!(
            alias_index.evicted_aliases.contains(oldest_alias),
            "evicted alias marker must track the oldest-created work item"
        );
        assert!(
            alias_index
                .spec_hash_by_work_id
                .contains_key("W-636-TS-0000"),
            "newer entries should be retained when an older-created item is present"
        );
    }

    #[test]
    fn ticket_alias_index_fails_closed_when_lossy_marker_capacity_saturates() {
        let mut alias_index = TicketAliasIndex::default();
        for idx in 0..MAX_TICKET_ALIAS_INDEX_EVICTED_ALIASES {
            alias_index
                .evicted_aliases
                .insert(format!("TCK-SATURATED-{idx}"));
        }

        let result = alias_index.mark_alias_evicted("TCK-SATURATED-OVERFLOW".to_string());
        assert!(
            result.is_err(),
            "lossy marker overflow must fail closed instead of growing unboundedly"
        );
        assert!(
            alias_index.evicted_aliases_saturated,
            "overflow must leave the index in saturated fail-closed state"
        );
    }

    #[test]
    fn resolve_ticket_alias_retries_after_transient_cas_failure() {
        let cas = Arc::new(FlakyCas::new(1));
        let spec_hash = store_work_spec_in_cas(
            cas.as_ref(),
            "W-636-RETRY-001",
            Some("TCK-RETRY-001"),
            1_000_000_000,
        );

        let emitter = Arc::new(crate::protocol::dispatch::StubLedgerEventEmitter::new());
        emitter.inject_raw_event(SignedLedgerEvent {
            event_id: "EVT-retry-opened-001".to_string(),
            event_type: "work.opened".to_string(),
            work_id: "W-636-RETRY-001".to_string(),
            actor_id: "actor:test".to_string(),
            payload: make_work_opened_session_envelope_payload(
                "W-636-RETRY-001",
                spec_hash.to_vec(),
            ),
            signature: vec![0u8; 64],
            timestamp_ns: 1_000_000_000,
        });

        let gate = ProjectionAliasReconciliationGate::new(emitter.clone())
            .with_cas(cas as Arc<dyn ContentAddressedStore>);

        let first = gate
            .resolve_ticket_alias("TCK-RETRY-001")
            .expect("first resolution attempt should not hard-fail");
        assert_eq!(
            first, None,
            "transient CAS failure must not poison index with a permanent miss"
        );

        // Trigger projection refresh with an unrelated event that does not
        // mention the failed work_id. Retry must still occur via projection
        // rescan of missing/stale spec-hash cache entries.
        emitter.inject_raw_event(SignedLedgerEvent {
            event_id: "EVT-retry-bump-001".to_string(),
            event_type: "non_work.bump".to_string(),
            work_id: "W-636-UNRELATED-001".to_string(),
            actor_id: "actor:test".to_string(),
            payload: Vec::new(),
            signature: vec![0u8; 64],
            timestamp_ns: 2_000_000_000,
        });

        let second = gate
            .resolve_ticket_alias("TCK-RETRY-001")
            .expect("second resolution attempt should not hard-fail");
        assert_eq!(
            second,
            Some("W-636-RETRY-001".to_string()),
            "alias must resolve after transient CAS failure clears"
        );
    }

    #[test]
    fn refresh_projection_reuses_spec_hash_cache_for_evicted_items() {
        let cas = Arc::new(CountingCas::new());
        let emitter = Arc::new(crate::protocol::dispatch::StubLedgerEventEmitter::new());

        let total_work_items = MAX_TICKET_ALIAS_INDEX_WORK_ITEMS + 16;
        for idx in 0..total_work_items {
            let work_id = format!("W-636-EVICT-{idx:04}");
            let ticket_alias = format!("TCK-636-EVICT-{idx:04}");
            let spec_hash = store_work_spec_in_cas(
                cas.as_ref(),
                &work_id,
                Some(&ticket_alias),
                (idx as u64 + 1) * 1_000_000_000,
            );
            emitter.inject_raw_event(SignedLedgerEvent {
                event_id: format!("EVT-evict-opened-{idx:04}"),
                event_type: "work.opened".to_string(),
                work_id: work_id.clone(),
                actor_id: "actor:test".to_string(),
                payload: make_work_opened_session_envelope_payload(&work_id, spec_hash.to_vec()),
                signature: vec![0u8; 64],
                timestamp_ns: (idx as u64 + 1) * 1_000_000_000,
            });
        }

        let target_idx = total_work_items - 1;
        let target_work_id = format!("W-636-EVICT-{target_idx:04}");
        let target_alias = format!("TCK-636-EVICT-{target_idx:04}");

        let gate = ProjectionAliasReconciliationGate::new(emitter.clone())
            .with_cas(cas.clone() as Arc<dyn ContentAddressedStore>);

        let first = gate
            .resolve_ticket_alias(&target_alias)
            .expect("first resolution should succeed");
        assert_eq!(first, Some(target_work_id.clone()));
        let retrieves_after_first = cas.retrieve_count();
        assert_eq!(
            retrieves_after_first, total_work_items,
            "initial refresh should decode each unique spec hash at most once"
        );

        // Force a projection refresh without changing any work spec hashes.
        emitter.inject_raw_event(SignedLedgerEvent {
            event_id: "EVT-evict-bump-001".to_string(),
            event_type: "non_work.bump".to_string(),
            work_id: target_work_id,
            actor_id: "actor:test".to_string(),
            payload: Vec::new(),
            signature: vec![0u8; 64],
            timestamp_ns: (total_work_items as u64 + 1) * 1_000_000_000,
        });

        gate.check_promotion(&[], 0)
            .expect("refresh for unchanged hashes should succeed");
        assert_eq!(
            cas.retrieve_count(),
            retrieves_after_first,
            "refresh on unchanged hashes must not trigger repeated CAS reads for evicted work"
        );
    }

    #[test]
    fn resolve_ticket_alias_scans_full_projection_beyond_max_work_list_rows() {
        let target_work_id = "W-636-CAP-9999";
        let target_alias = "TCK-636-BEYOND-CAP";
        let (cas, target_hash) = setup_cas_with_work_spec(target_work_id, Some(target_alias));

        let emitter = crate::protocol::dispatch::StubLedgerEventEmitter::new();

        // Populate exactly MAX_WORK_LIST_ROWS work items that do NOT resolve,
        // then place the real alias mapping after that boundary.
        for idx in 0..MAX_WORK_LIST_ROWS {
            let work_id = format!("W-636-CAP-{idx:04}");
            emitter.inject_raw_event(SignedLedgerEvent {
                event_id: format!("EVT-opened-cap-{idx}"),
                event_type: "work.opened".to_string(),
                work_id,
                actor_id: "actor:test".to_string(),
                payload: make_work_opened_session_envelope_payload(
                    &format!("W-636-CAP-{idx:04}"),
                    vec![0xAA; 32],
                ),
                signature: vec![0u8; 64],
                timestamp_ns: (idx as u64 + 1) * 1_000_000_000,
            });
        }

        emitter.inject_raw_event(SignedLedgerEvent {
            event_id: "EVT-opened-cap-target".to_string(),
            event_type: "work.opened".to_string(),
            work_id: target_work_id.to_string(),
            actor_id: "actor:test".to_string(),
            payload: make_work_opened_session_envelope_payload(
                target_work_id,
                target_hash.to_vec(),
            ),
            signature: vec![0u8; 64],
            timestamp_ns: (MAX_WORK_LIST_ROWS as u64 + 1) * 1_000_000_000,
        });

        let gate = ProjectionAliasReconciliationGate::new(Arc::new(emitter))
            .with_cas(cas as Arc<dyn apm2_core::evidence::ContentAddressedStore>);

        let result = gate.resolve_ticket_alias(target_alias);
        assert_eq!(
            result.expect("alias resolution should not error"),
            Some(target_work_id.to_string()),
            "alias resolution must scan beyond MAX_WORK_LIST_ROWS without truncation"
        );
    }

    #[test]
    fn alias_reconciliation_gate_blocks_promotion_on_mismatch() {
        let (cas, spec_hash) = setup_cas_with_work_spec("W-636-GATE-001", Some("TCK-GATE-001"));

        let emitter = make_emitter_with_work(&[("W-636-GATE-001", spec_hash.to_vec())]);

        let gate = ProjectionAliasReconciliationGate::new(emitter)
            .with_cas(cas as Arc<dyn apm2_core::evidence::ContentAddressedStore>);

        // Supply a binding with a mismatched canonical_work_id (wrong hash)
        let wrong_hash = [0xFF; 32];
        let bindings = vec![TicketAliasBinding {
            ticket_alias: "TCK-GATE-001".to_string(),
            canonical_work_id: wrong_hash,
            observed_at_tick: 50,
            observation_window_start: 0,
            observation_window_end: 100,
        }];

        let result = gate
            .check_promotion(&bindings, 50)
            .expect("should not error");
        assert!(
            !promotion_gate(&result),
            "mismatched canonical_work_id must block promotion (fail-closed)"
        );
        assert!(
            !result.unresolved_defects.is_empty(),
            "mismatched binding must produce defects"
        );
    }

    #[test]
    fn alias_reconciliation_with_cas_enriches_projections() {
        let (cas, spec_hash) = setup_cas_with_work_spec("W-636-ENRICH-001", Some("TCK-ENRICH-001"));

        let emitter = make_emitter_with_work(&[("W-636-ENRICH-001", spec_hash.to_vec())]);

        let gate = ProjectionAliasReconciliationGate::new(emitter)
            .with_cas(cas as Arc<dyn apm2_core::evidence::ContentAddressedStore>);

        // Supply a binding using the ticket alias as the alias key, with
        // the correct work_id hash as canonical_work_id.
        let correct_hash = work_id_to_hash("W-636-ENRICH-001");
        let bindings = vec![TicketAliasBinding {
            ticket_alias: "TCK-ENRICH-001".to_string(),
            canonical_work_id: correct_hash,
            observed_at_tick: 50,
            observation_window_start: 0,
            observation_window_end: 100,
        }];

        let result = gate
            .check_promotion(&bindings, 50)
            .expect("should not error");
        assert!(
            promotion_gate(&result),
            "matching alias binding with CAS-enriched projection must pass promotion"
        );
        assert_eq!(result.resolved_count, 1, "one binding should be resolved");
    }
}
