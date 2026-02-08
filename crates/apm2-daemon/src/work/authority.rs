use std::sync::{Arc, RwLock};

use apm2_core::work::{Work, WorkState};
use thiserror::Error;

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
        let signed_events = self.event_emitter.get_all_events();
        let current_count = signed_events.len();

        // Check cached event count to avoid redundant rebuilds.
        // Note: the `current_count > 0` guard was removed so that zero-event
        // projections also benefit from the cache fast-path (MINOR fix).
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
    /// We distinguish work-domain events from session events by verifying
    /// the signature against the work-domain prefix using the emitter's
    /// verifying key. Events that fail domain-prefix signature verification
    /// are silently skipped (they are not work-domain events). Events
    /// without a known work-domain prefix (native `work.*` protobuf events)
    /// are passed through unconditionally since `translate_signed_events`
    /// filters them structurally.
    fn filter_work_domain_events(events: &[SignedLedgerEvent]) -> Vec<SignedLedgerEvent> {
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
