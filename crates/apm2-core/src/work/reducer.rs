//! Work lifecycle reducer implementation.

use std::collections::{HashMap, VecDeque};

use prost::Message;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::error::WorkError;
use super::state::{Work, WorkState, WorkType};
use crate::events::{DefectRecorded, DefectSource, WorkEvent, work_event};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

/// The designated actor ID for the CI system processor.
///
/// Only events signed by this actor can transition work items from CI-gated
/// states (`CiPending`). This prevents arbitrary agents from bypassing CI
/// gating by emitting `WorkTransitioned` events.
///
/// # Security
///
/// This constant defines the system-level identity that the CI event processor
/// must use when signing transition events. The value uses a `system:` prefix
/// to distinguish it from regular agent identities.
pub const CI_SYSTEM_ACTOR_ID: &str = "system:ci-processor";

/// State maintained by the work reducer.
///
/// Maps work IDs to their current state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkReducerState {
    /// Map of work ID to work item.
    pub work_items: HashMap<String, Work>,
    /// Latest authoritative changeset digest per work ID, derived from
    /// `changeset_published` events.
    pub latest_changeset_by_work: HashMap<String, [u8; 32]>,
    /// Last observed CI-bound gate digest per work ID.
    pub ci_receipt_digest_by_work: HashMap<String, [u8; 32]>,
    /// Last observed review receipt digest per work ID.
    pub review_receipt_digest_by_work: HashMap<String, [u8; 32]>,
    /// Last observed merge receipt digest per work ID.
    pub merge_receipt_digest_by_work: HashMap<String, [u8; 32]>,
    /// Event ID of the `ChangeSetPublished` event that established the latest
    /// changeset identity binding, keyed by work ID (`STEP_10`).
    pub changeset_published_event_id_by_work: HashMap<String, String>,
    /// CAS hash (32 bytes) of the `ChangeSetBundleV1` for the latest
    /// changeset, keyed by work ID (`STEP_10`).
    pub bundle_cas_hash_by_work: HashMap<String, [u8; 32]>,
}

impl WorkReducerState {
    /// Creates a new empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of work items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.work_items.len()
    }

    /// Returns `true` if there are no work items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.work_items.is_empty()
    }

    /// Returns the work item for a given ID, if it exists.
    #[must_use]
    pub fn get(&self, work_id: &str) -> Option<&Work> {
        self.work_items.get(work_id)
    }

    /// Returns the number of active (non-terminal) work items.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.work_items.values().filter(|w| w.is_active()).count()
    }

    /// Returns the number of completed work items.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.work_items
            .values()
            .filter(|w| w.state == WorkState::Completed)
            .count()
    }

    /// Returns the number of aborted work items.
    #[must_use]
    pub fn aborted_count(&self) -> usize {
        self.work_items
            .values()
            .filter(|w| w.state == WorkState::Aborted)
            .count()
    }

    /// Returns all work items in a specific state.
    #[must_use]
    pub fn in_state(&self, state: WorkState) -> Vec<&Work> {
        self.work_items
            .values()
            .filter(|w| w.state == state)
            .collect()
    }

    /// Returns all active work items (non-terminal states).
    #[must_use]
    pub fn active_work(&self) -> Vec<&Work> {
        self.work_items.values().filter(|w| w.is_active()).collect()
    }

    /// Returns work items by requirement ID.
    #[must_use]
    pub fn by_requirement(&self, requirement_id: &str) -> Vec<&Work> {
        self.work_items
            .values()
            .filter(|w| w.requirement_ids.contains(&requirement_id.to_string()))
            .collect()
    }

    /// Returns the work item associated with a PR number, if any.
    ///
    /// # CI Gating
    ///
    /// This method is used to match `CIWorkflowCompleted` events to work items
    /// for phase transitions.
    #[must_use]
    pub fn by_pr_number(&self, pr_number: u64) -> Option<&Work> {
        self.work_items
            .values()
            .find(|w| w.pr_number == Some(pr_number))
    }

    /// Returns all work items in CI-gated states (`CiPending` or `Blocked`).
    ///
    /// # CI Gating
    ///
    /// These work items are waiting for CI events to trigger phase transitions.
    #[must_use]
    pub fn ci_gated_work(&self) -> Vec<&Work> {
        self.work_items
            .values()
            .filter(|w| {
                matches!(
                    w.state,
                    crate::work::WorkState::CiPending | crate::work::WorkState::Blocked
                )
            })
            .collect()
    }

    /// Returns all work items that are claimable (`Open` or `ReadyForReview`).
    ///
    /// # CI Gating
    ///
    /// Only these work items can be claimed by agents. Work items in
    /// `CiPending` or `Blocked` states cannot be claimed.
    #[must_use]
    pub fn claimable_work(&self) -> Vec<&Work> {
        self.work_items
            .values()
            .filter(|w| w.state.is_claimable())
            .collect()
    }
}

/// Maximum number of identity-chain defect records retained in memory.
///
/// When the buffer is at capacity, the oldest entry is evicted before
/// appending a new one.  This prevents unbounded memory growth when
/// `drain_identity_chain_defects()` is not called (or called
/// infrequently) while a flood of stale-digest / cross-work injection
/// events is processed.
pub const MAX_IDENTITY_CHAIN_DEFECTS: usize = 1_000;

/// Reducer for work lifecycle events.
///
/// Processes work events and maintains the state of all work items.
/// Implements the state machine:
///
/// ```text
/// (none) --WorkOpened--> Open
/// Open --WorkTransitioned--> Claimed
/// Claimed --WorkTransitioned--> InProgress | Open
/// InProgress --WorkTransitioned--> Review | NeedsInput | NeedsAdjudication
/// Review --WorkTransitioned--> InProgress
/// Review --WorkCompleted--> Completed
/// Any active --WorkAborted--> Aborted
/// ```
#[derive(Debug, Default)]
pub struct WorkReducer {
    state: WorkReducerState,
    /// Structured defect records for identity-chain violations (`STEP_09`).
    ///
    /// Accumulated during event processing. Consumers should drain this
    /// after each reduce cycle to persist defects via the ledger.
    ///
    /// Bounded by [`MAX_IDENTITY_CHAIN_DEFECTS`]; oldest entries are
    /// evicted when at capacity (ring-buffer semantics via `VecDeque`).
    identity_chain_defects: VecDeque<DefectRecorded>,
}

impl WorkReducer {
    const PR_REBIND_RATIONALE_CODE: &str = "pr_rebound_ticket_work_id";

    /// Creates a new work reducer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drains accumulated identity-chain defect records (`STEP_09`).
    ///
    /// Consumers should call this after each reduce cycle to retrieve and
    /// persist defect records via the ledger.
    pub fn drain_identity_chain_defects(&mut self) -> Vec<DefectRecorded> {
        std::mem::take(&mut self.identity_chain_defects).into()
    }

    /// Returns the number of pending identity-chain defects.
    #[must_use]
    pub fn identity_chain_defect_count(&self) -> usize {
        self.identity_chain_defects.len()
    }

    /// Appends a defect record, evicting the oldest entry when the
    /// buffer is at [`MAX_IDENTITY_CHAIN_DEFECTS`] capacity.
    ///
    /// O(1) amortised: `VecDeque::pop_front` and `push_back` are both
    /// O(1).
    fn push_defect(&mut self, defect: DefectRecorded) {
        if self.identity_chain_defects.len() >= MAX_IDENTITY_CHAIN_DEFECTS {
            self.identity_chain_defects.pop_front();
        }
        self.identity_chain_defects.push_back(defect);
    }

    /// Canonical merge receipt event types (explicit allowlist).
    ///
    /// Replaces substring matching to prevent cross-work state injection via
    /// unreserved event types that contain `merge_receipt`.
    const MERGE_RECEIPT_EVENT_TYPES: &'static [&'static str] = &[
        "fac.merge_receipt.recorded",
        "gate.merge_receipt_created",
        "merge_receipt_recorded",
        "merge_receipt_created",
    ];

    /// Records latest-digest projections from non-work events.
    ///
    /// This keeps stage-bound digest context available when processing
    /// `work.transitioned` / `work.completed` boundaries.
    ///
    /// # Security
    ///
    /// Digest state updates are bound to `EventRecord.work_id` (the signed
    /// envelope field), NOT the payload-extracted `work_id`. If the payload
    /// `work_id` does not match the envelope `work_id`, a security warning
    /// is logged and the event is skipped, preventing cross-work state
    /// injection attacks.
    fn observe_changeset_bound_event(&mut self, event: &EventRecord) {
        let Some((payload_work_id, changeset_digest)) =
            extract_work_id_and_digest_from_payload(&event.payload)
        else {
            return;
        };

        // Bind to signed envelope identity: use EventRecord.session_id as the
        // authoritative work_id for state updates. Validate that payload
        // work_id matches the envelope to prevent cross-work injection.
        let envelope_work_id = &event.session_id;

        // If the envelope work_id is empty (some legacy events), fall back to
        // payload work_id but only for changeset_published (which populates
        // the index). For all receipt types, require envelope binding.
        let authoritative_work_id = if envelope_work_id.is_empty() {
            if event.event_type == "changeset_published" {
                payload_work_id
            } else {
                warn!(
                    event_type = %event.event_type,
                    payload_work_id = %payload_work_id,
                    "digest-bound event skipped: empty envelope work_id on non-publication event"
                );
                return;
            }
        } else {
            if payload_work_id != *envelope_work_id {
                warn!(
                    event_type = %event.event_type,
                    envelope_work_id = %envelope_work_id,
                    payload_work_id = %payload_work_id,
                    defect_code = "CROSS_WORK_INJECTION_ATTEMPT",
                    "SECURITY: digest-bound event skipped: payload work_id does not match \
                     signed envelope work_id — possible cross-work state injection"
                );
                self.record_cross_work_injection_defect(
                    &event.event_type,
                    envelope_work_id,
                    &payload_work_id,
                    event.timestamp_ns,
                );
                return;
            }
            envelope_work_id.clone()
        };

        match event.event_type.as_str() {
            "changeset_published" => {
                self.record_changeset_published(event, authoritative_work_id, changeset_digest);
            },
            // CI transitions are driven by gate receipts (not lease issuance).
            // Enforce latest-digest validation: only receipts whose digest
            // matches work_latest_changeset are admissible (CSID-004).
            // Stale receipts are silently ignored with a structured log.
            "gate.receipt_collected"
            | "gate_receipt_collected"
            | "gate.receipt"
            | "gate_receipt" => {
                if self.is_digest_latest(&authoritative_work_id, changeset_digest) {
                    self.state
                        .ci_receipt_digest_by_work
                        .insert(authoritative_work_id, changeset_digest);
                } else {
                    self.record_stale_digest_defect(
                        "gate_receipt",
                        &event.event_type,
                        &authoritative_work_id,
                        changeset_digest,
                    );
                }
            },
            "review_receipt_recorded" | "review_blocked_recorded" => {
                if self.is_digest_latest(&authoritative_work_id, changeset_digest) {
                    self.state
                        .review_receipt_digest_by_work
                        .insert(authoritative_work_id, changeset_digest);
                } else {
                    self.record_stale_digest_defect(
                        "review_receipt",
                        &event.event_type,
                        &authoritative_work_id,
                        changeset_digest,
                    );
                }
            },
            // Merge receipt events: explicit allowlist (no substring matching).
            event_type if Self::MERGE_RECEIPT_EVENT_TYPES.contains(&event_type) => {
                if self.is_digest_latest(&authoritative_work_id, changeset_digest) {
                    self.state
                        .merge_receipt_digest_by_work
                        .insert(authoritative_work_id, changeset_digest);
                } else {
                    self.record_stale_digest_defect(
                        "merge_receipt",
                        event_type,
                        &authoritative_work_id,
                        changeset_digest,
                    );
                }
            },
            _ => {},
        }
    }

    /// Records a `changeset_published` event's digest, event ID, and CAS hash
    /// into projection state (`STEP_10`).
    fn record_changeset_published(
        &mut self,
        event: &EventRecord,
        authoritative_work_id: String,
        changeset_digest: [u8; 32],
    ) {
        self.state
            .latest_changeset_by_work
            .insert(authoritative_work_id.clone(), changeset_digest);
        let event_id = event
            .seq_id
            .map_or_else(|| "unknown".to_string(), |s| format!("seq-{s}"));
        self.state
            .changeset_published_event_id_by_work
            .insert(authoritative_work_id.clone(), event_id);
        if let Some(cas_hash) = extract_cas_hash_from_payload(&event.payload) {
            self.state
                .bundle_cas_hash_by_work
                .insert(authoritative_work_id, cas_hash);
        }
    }

    /// Returns `true` when `incoming` matches the latest authoritative
    /// changeset digest for `work_id`.
    fn is_digest_latest(&self, work_id: &str, incoming: [u8; 32]) -> bool {
        self.state
            .latest_changeset_by_work
            .get(work_id)
            .is_some_and(|latest| *latest == incoming)
    }

    /// Records a structured identity-chain defect for a stale or unbound
    /// changeset digest observation (`STEP_09`).
    ///
    /// Replaces warn-only logging with a machine-readable `DefectRecorded`
    /// that is accumulated in `WorkReducer::identity_chain_defects`.
    fn record_stale_digest_defect(
        &mut self,
        stage: &str,
        event_type: &str,
        work_id: &str,
        incoming_digest: [u8; 32],
    ) {
        let latest = self
            .state
            .latest_changeset_by_work
            .get(work_id)
            .map_or_else(|| "unknown".to_string(), hex::encode);
        warn!(
            stage,
            event_type,
            work_id,
            incoming_digest = %hex::encode(incoming_digest),
            latest_digest = %latest,
            "stale or unbound changeset digest ignored by work reducer"
        );

        let reason = format!(
            "STALE_DIGEST:{stage}:{event_type}:{work_id}:incoming={},latest={latest}",
            hex::encode(incoming_digest),
        );
        let cas_hash =
            hash_defect_preimage(work_id.as_bytes(), &incoming_digest, reason.as_bytes());

        // Deterministic defect ID derived from the CAS hash (first 16 bytes
        // hex-encoded). This ensures replay consistency: the same inputs
        // always produce the same defect_id, which is required because the
        // WorkReducer must be a pure function of its input events.
        let defect_id = format!("DEF-IDENTITY-CHAIN-{}", hex::encode(&cas_hash[..16]));

        self.push_defect(DefectRecorded {
            defect_id,
            defect_type: "IDENTITY_CHAIN_STALE_DIGEST".to_string(),
            cas_hash: cas_hash.to_vec(),
            source: DefectSource::ProjectionTamper as i32,
            work_id: work_id.to_string(),
            severity: "S2".to_string(),
            detected_at: 0,
            time_envelope_ref: None,
        });
    }

    /// Records a structured defect for a cross-work injection attempt.
    fn record_cross_work_injection_defect(
        &mut self,
        event_type: &str,
        envelope_work_id: &str,
        payload_work_id: &str,
        detected_at_ns: u64,
    ) {
        let reason = format!(
            "CROSS_WORK_INJECTION:{event_type}:envelope={envelope_work_id},payload={payload_work_id}",
        );
        let cas_hash = hash_defect_preimage(
            envelope_work_id.as_bytes(),
            payload_work_id.as_bytes(),
            reason.as_bytes(),
        );

        // Deterministic defect ID derived from the CAS hash (first 16 bytes
        // hex-encoded). Same rationale as `record_stale_digest_defect`.
        let defect_id = format!("DEF-IDENTITY-CHAIN-{}", hex::encode(&cas_hash[..16]));

        self.push_defect(DefectRecorded {
            defect_id,
            defect_type: "IDENTITY_CHAIN_CROSS_WORK_INJECTION".to_string(),
            cas_hash: cas_hash.to_vec(),
            source: DefectSource::ProjectionTamper as i32,
            work_id: envelope_work_id.to_string(),
            severity: "S1".to_string(),
            detected_at: detected_at_ns,
            time_envelope_ref: None,
        });
    }

    /// Returns the latest authoritative changeset digest for `work_id`.
    fn latest_changeset_digest(&self, work_id: &str) -> Option<[u8; 32]> {
        self.state.latest_changeset_by_work.get(work_id).copied()
    }

    /// Enforces stage-boundary transition guards with latest-digest admission.
    ///
    /// Two stage boundaries are guarded (CSID-004):
    ///
    /// 1. **CI transition** (`CiPending -> ReadyForReview/Blocked`): the most
    ///    recent gate receipt digest must equal `work_latest_changeset`.
    /// 2. **Review start** (`ReadyForReview -> Review`): a latest-digest review
    ///    receipt must exist (ensuring review is bound to the current
    ///    changeset). When no review receipt is available yet, the transition
    ///    is allowed because the review receipt will be validated at
    ///    completion/merge admission.
    ///
    /// Returns:
    /// - `Ok(true)` when transition admission checks pass.
    /// - `Ok(false)` when transition must be denied as stale/unbound.
    /// - `Err(...)` for explicit unauthorized transition attempts.
    fn enforce_stage_boundary_guards(
        &mut self,
        work_id: &str,
        from_state: WorkState,
        to_state: WorkState,
        rationale: &str,
        actor_id: &str,
    ) -> Result<bool, WorkError> {
        // ---- CI stage boundary ----
        if from_state == WorkState::CiPending {
            if rationale != "ci_passed" && rationale != "ci_failed" {
                return Err(WorkError::CiGatedTransitionUnauthorized {
                    from_state,
                    to_state,
                    rationale_code: rationale.to_string(),
                });
            }
            if actor_id != CI_SYSTEM_ACTOR_ID {
                return Err(WorkError::CiGatedTransitionUnauthorizedActor {
                    from_state,
                    actor_id: actor_id.to_string(),
                });
            }
            if matches!(to_state, WorkState::ReadyForReview | WorkState::Blocked) {
                // Fail-closed: a published changeset MUST exist before any
                // CI stage boundary transition is admitted (CSID-004).
                let Some(latest_digest) = self.latest_changeset_digest(work_id) else {
                    warn!(
                        work_id,
                        event_type = "work.transitioned",
                        from_state = %from_state.as_str(),
                        to_state = %to_state.as_str(),
                        defect_code = "MISSING_CHANGESET_PUBLISHED",
                        "ci transition denied: no changeset published for work (fail-closed)"
                    );
                    return Ok(false);
                };
                let Some(incoming_digest) =
                    self.state.ci_receipt_digest_by_work.get(work_id).copied()
                else {
                    warn!(
                        work_id,
                        event_type = "work.transitioned",
                        from_state = %from_state.as_str(),
                        to_state = %to_state.as_str(),
                        latest_digest = %hex::encode(latest_digest),
                        "ci transition denied: no changeset-bound gate receipt observed"
                    );
                    return Ok(false);
                };
                if incoming_digest != latest_digest {
                    self.record_stale_digest_defect(
                        "ci_transition",
                        "work.transitioned",
                        work_id,
                        incoming_digest,
                    );
                    return Ok(false);
                }
            }
        }

        // ---- Review start stage boundary (CSID-004) ----
        //
        // When transitioning to Review from ANY state (ReadyForReview,
        // InProgress, etc.), verify that a latest changeset exists
        // (fail-closed). If a review receipt has already been observed but
        // its digest is stale, deny the transition (the review was for an
        // older changeset and must be re-done).
        //
        // This guard covers both CI-gated workflows (ReadyForReview ->
        // Review) and non-CI-gated workflows (InProgress -> Review).
        if to_state == WorkState::Review {
            // Fail-closed: a published changeset MUST exist before review
            // start is admitted (CSID-004).
            let Some(_latest_digest) = self.latest_changeset_digest(work_id) else {
                warn!(
                    work_id,
                    event_type = "work.transitioned",
                    from_state = %from_state.as_str(),
                    to_state = %to_state.as_str(),
                    defect_code = "MISSING_CHANGESET_PUBLISHED",
                    "review start denied: no changeset published for work (fail-closed)"
                );
                return Ok(false);
            };
            // If a review receipt already exists but is stale, deny.
            if let Some(review_digest) = self
                .state
                .review_receipt_digest_by_work
                .get(work_id)
                .copied()
            {
                if !self.is_digest_latest(work_id, review_digest) {
                    self.record_stale_digest_defect(
                        "review_start",
                        "work.transitioned",
                        work_id,
                        review_digest,
                    );
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Validates gate/merge receipt field separation for completion payloads.
    fn validate_completion_receipt_fields(
        work_id: &str,
        event: &crate::events::WorkCompleted,
    ) -> Result<(), WorkError> {
        if event
            .gate_receipt_id
            .to_ascii_lowercase()
            .starts_with("merge-receipt-")
        {
            return Err(WorkError::MergeReceiptInGateReceiptField {
                work_id: work_id.to_string(),
                value: event.gate_receipt_id.clone(),
            });
        }

        if !event.merge_receipt_id.is_empty()
            && !event
                .merge_receipt_id
                .to_ascii_lowercase()
                .starts_with("merge-receipt-")
        {
            return Err(WorkError::InvalidMergeReceiptId {
                work_id: work_id.to_string(),
                value: event.merge_receipt_id.clone(),
            });
        }
        Ok(())
    }

    /// Returns the digest context used for merge admission.
    fn completion_incoming_digest(
        &self,
        work_id: &str,
        merge_receipt_id: &str,
    ) -> Option<[u8; 32]> {
        if merge_receipt_id.is_empty() {
            self.state
                .review_receipt_digest_by_work
                .get(work_id)
                .copied()
        } else {
            self.state
                .merge_receipt_digest_by_work
                .get(work_id)
                .copied()
        }
    }

    /// Enforces latest-digest merge admission. Returns `true` if admissible.
    ///
    /// Fail-closed: when no changeset has been published for this work (no
    /// entry in `latest_changeset_by_work`), completion is denied. A published
    /// changeset is required for merge admission (CSID-004).
    fn completion_latest_digest_admitted(&mut self, work_id: &str, merge_receipt_id: &str) -> bool {
        let Some(latest_digest) = self.latest_changeset_digest(work_id) else {
            // Fail-closed: no changeset published — deny completion.
            warn!(
                work_id,
                event_type = "work.completed",
                defect_code = "MISSING_CHANGESET_PUBLISHED",
                "work completion denied: no changeset published for work (fail-closed)"
            );
            return false;
        };
        let Some(incoming_digest) = self.completion_incoming_digest(work_id, merge_receipt_id)
        else {
            warn!(
                work_id,
                event_type = "work.completed",
                latest_digest = %hex::encode(latest_digest),
                merge_receipt_id = %merge_receipt_id,
                "work completion denied: no admissible changeset-bound receipt observed"
            );
            return false;
        };
        if incoming_digest != latest_digest {
            self.record_stale_digest_defect(
                "merge_admission",
                "work.completed",
                work_id,
                incoming_digest,
            );
            return false;
        }
        true
    }

    /// Handles a work opened event.
    fn handle_opened(
        &mut self,
        event: crate::events::WorkOpened,
        timestamp: u64,
    ) -> Result<(), WorkError> {
        let work_id = event.work_id.clone();

        // Check if work already exists
        if self.state.work_items.contains_key(&work_id) {
            return Err(WorkError::WorkAlreadyExists { work_id });
        }

        // Strict parsing: reject unknown work types
        let work_type = WorkType::parse(&event.work_type)?;

        // Create new work item
        let work = Work::new(
            work_id.clone(),
            work_type,
            event.spec_snapshot_hash,
            event.requirement_ids,
            event.parent_work_ids,
            timestamp,
        );

        self.state.work_items.insert(work_id, work);
        Ok(())
    }

    /// Handles a work transitioned event.
    ///
    /// # Arguments
    ///
    /// * `event` - The transition event payload
    /// * `timestamp` - Event timestamp
    /// * `actor_id` - The actor ID from the event record (signer identity)
    fn handle_transitioned(
        &mut self,
        event: crate::events::WorkTransitioned,
        timestamp: u64,
        actor_id: &str,
    ) -> Result<(), WorkError> {
        let work_id = &event.work_id;

        let current_work =
            self.state
                .work_items
                .get(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Verify work is not in a terminal state
        if current_work.is_terminal() {
            return Err(WorkError::InvalidTransition {
                from_state: current_work.state.as_str().to_string(),
                event_type: "work.transitioned".to_string(),
            });
        }

        // Strict parsing: reject unknown states
        let from_state = WorkState::parse(&event.from_state)?;
        let to_state = WorkState::parse(&event.to_state)?;

        // Verify the from_state matches current state
        if current_work.state != from_state {
            return Err(WorkError::InvalidTransition {
                from_state: current_work.state.as_str().to_string(),
                event_type: format!(
                    "work.transitioned (expected from_state={}, got={})",
                    current_work.state.as_str(),
                    event.from_state
                ),
            });
        }

        // Replay protection: validate sequence via previous_transition_count
        // All transitions MUST provide the correct sequence to prevent replay attacks
        let expected_count = current_work.transition_count;
        if event.previous_transition_count != expected_count {
            return Err(WorkError::SequenceMismatch {
                work_id: work_id.clone(),
                expected: expected_count,
                actual: event.previous_transition_count,
            });
        }

        // Verify the transition is allowed
        if !from_state.can_transition_to(&to_state) {
            return Err(WorkError::TransitionNotAllowed {
                from_state,
                to_state,
            });
        }

        if !self.enforce_stage_boundary_guards(
            work_id,
            from_state,
            to_state,
            &event.rationale_code,
            actor_id,
        )? {
            return Ok(());
        }

        let work =
            self.state
                .work_items
                .get_mut(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Apply the transition
        work.state = to_state;
        work.last_transition_at = timestamp;
        work.transition_count += 1;
        work.last_rationale_code = event.rationale_code;

        // Record first claim timestamp (immutable once set).
        if to_state == WorkState::Claimed && work.claimed_at.is_none() {
            work.claimed_at = Some(timestamp);
        }

        Ok(())
    }

    /// Handles a work completed event.
    fn handle_completed(
        &mut self,
        event: crate::events::WorkCompleted,
        timestamp: u64,
    ) -> Result<(), WorkError> {
        let work_id = &event.work_id;

        let current_work =
            self.state
                .work_items
                .get(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Can only complete from Review state
        if current_work.state != WorkState::Review {
            return Err(WorkError::InvalidTransition {
                from_state: current_work.state.as_str().to_string(),
                event_type: "work.completed".to_string(),
            });
        }

        // Must have evidence
        if event.evidence_ids.is_empty() && event.evidence_bundle_hash.is_empty() {
            return Err(WorkError::CompletionWithoutEvidence {
                work_id: work_id.clone(),
            });
        }

        // --- Domain separation: gate_receipt_id vs merge_receipt_id ---
        //
        // INV-0113 (fail-closed): gate_receipt_id MUST NOT contain a merge
        // receipt identifier.  Any value whose ASCII-lowercase form starts
        // with "merge-receipt-" is rejected.  Case-insensitive comparison
        // prevents bypass via case-variant prefixes (e.g. "MERGE-RECEIPT-",
        // "Merge-Receipt-").
        //
        // INV-0114 (positive allowlist): merge_receipt_id, when non-empty,
        // MUST start with "merge-receipt-" (case-insensitive).  This
        // prevents gate receipt identifiers from being injected into the
        // merge field.
        //
        // Together these two checks enforce bidirectional domain separation
        // at the reducer boundary.

        Self::validate_completion_receipt_fields(work_id, &event)?;
        if !self.completion_latest_digest_admitted(work_id, &event.merge_receipt_id) {
            return Ok(());
        }

        let work =
            self.state
                .work_items
                .get_mut(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Apply completion (all deny gates passed — safe to mutate)
        work.state = WorkState::Completed;
        work.last_transition_at = timestamp;
        work.transition_count += 1;
        work.evidence_bundle_hash = Some(event.evidence_bundle_hash);
        work.evidence_ids = event.evidence_ids;
        work.gate_receipt_id = if event.gate_receipt_id.is_empty() {
            None
        } else {
            Some(event.gate_receipt_id)
        };
        work.merge_receipt_id = if event.merge_receipt_id.is_empty() {
            None
        } else {
            Some(event.merge_receipt_id)
        };

        Ok(())
    }

    /// Handles a work aborted event.
    fn handle_aborted(
        &mut self,
        event: crate::events::WorkAborted,
        timestamp: u64,
    ) -> Result<(), WorkError> {
        let work_id = &event.work_id;

        let work =
            self.state
                .work_items
                .get_mut(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Cannot abort already terminal work
        if work.is_terminal() {
            return Err(WorkError::InvalidTransition {
                from_state: work.state.as_str().to_string(),
                event_type: "work.aborted".to_string(),
            });
        }

        // Apply abort
        work.state = WorkState::Aborted;
        work.last_transition_at = timestamp;
        work.transition_count += 1;
        work.abort_reason = Some(event.abort_reason);
        work.last_rationale_code = event.rationale_code;

        Ok(())
    }

    /// Handles a work PR associated event.
    ///
    /// # CI Gating
    ///
    /// Associates a PR number with a work item, enabling CI event matching
    /// for phase transitions.
    ///
    /// # Security Constraints
    ///
    /// - **State Restriction**: PR association is only allowed when the work
    ///   item is in `Claimed` or `InProgress` state. This permits manual
    ///   operator-supervised push flows before explicit `InProgress`
    ///   transition, while still preventing CI-gating bypass from
    ///   `CiPending`/`Blocked` and terminal states.
    ///
    /// - **Uniqueness Constraint (CTR-CIQ002)**: A PR number cannot be
    ///   associated with a work item if it is already associated with another
    ///   active (non-terminal) work item. This prevents CI result confusion.
    fn handle_pr_associated(
        &mut self,
        event: &crate::events::WorkPrAssociated,
        timestamp: u64,
    ) -> Result<(), WorkError> {
        let work_id = &event.work_id;
        let pr_number = event.pr_number;
        let commit_sha = &event.commit_sha;

        // Security check: Verify PR number is not already associated with another
        // active work item (CTR-CIQ002 uniqueness constraint)
        if let Some(existing_work_id) = self
            .state
            .work_items
            .values()
            .find(|w| w.pr_number == Some(pr_number) && w.is_active() && w.work_id != *work_id)
            .map(|w| w.work_id.clone())
        {
            // Migration recovery: during ledger replay, permit rebinding from a
            // legacy non-ticket work ID (e.g. UUID-based) to a canonical
            // ticket work ID (`W-TCK-*`). This prevents historical mixed-ID
            // ledgers from bricking projection rebuild after canonicalization.
            if Self::allow_ticket_work_rebind(work_id, &existing_work_id) {
                self.abort_superseded_work_for_pr_rebind(&existing_work_id, work_id, timestamp)?;
            } else {
                return Err(WorkError::PrNumberAlreadyAssociated {
                    pr_number,
                    existing_work_id,
                });
            }
        }

        let work =
            self.state
                .work_items
                .get_mut(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Security check: PR association only allowed from Claimed or
        // InProgress state.
        if !matches!(work.state, WorkState::Claimed | WorkState::InProgress) {
            return Err(WorkError::PrAssociationNotAllowed {
                work_id: work_id.clone(),
                current_state: work.state,
            });
        }

        // Set the PR number and commit SHA for CI event matching
        work.pr_number = Some(pr_number);
        work.commit_sha = Some(commit_sha.clone());

        Ok(())
    }

    #[inline]
    fn is_canonical_ticket_work_id(work_id: &str) -> bool {
        let Some(ticket_suffix) = work_id.strip_prefix("W-TCK-") else {
            return false;
        };
        !ticket_suffix.is_empty() && ticket_suffix.bytes().all(|byte| byte.is_ascii_digit())
    }

    #[inline]
    fn allow_ticket_work_rebind(incoming_work_id: &str, existing_work_id: &str) -> bool {
        Self::is_canonical_ticket_work_id(incoming_work_id)
            && !Self::is_canonical_ticket_work_id(existing_work_id)
    }

    fn abort_superseded_work_for_pr_rebind(
        &mut self,
        existing_work_id: &str,
        incoming_work_id: &str,
        timestamp: u64,
    ) -> Result<(), WorkError> {
        let existing_work = self
            .state
            .work_items
            .get_mut(existing_work_id)
            .ok_or_else(|| WorkError::WorkNotFound {
                work_id: existing_work_id.to_string(),
            })?;

        if existing_work.is_terminal() {
            return Ok(());
        }

        existing_work.state = WorkState::Aborted;
        existing_work.last_transition_at = timestamp;
        existing_work.transition_count = existing_work.transition_count.saturating_add(1);
        existing_work.last_rationale_code = Self::PR_REBIND_RATIONALE_CODE.to_string();
        existing_work.abort_reason = Some(format!(
            "superseded by canonical ticket work_id '{incoming_work_id}' during PR rebind replay"
        ));

        Ok(())
    }
}

impl Reducer for WorkReducer {
    type State = WorkReducerState;
    type Error = WorkError;

    fn name(&self) -> &'static str {
        "work-lifecycle"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        self.observe_changeset_bound_event(event);

        // Only handle work events
        if !event.event_type.starts_with("work.") {
            return Ok(());
        }

        let work_event = WorkEvent::decode(&event.payload[..])?;
        let timestamp = event.timestamp_ns;
        let actor_id = &event.actor_id;

        match work_event.event {
            Some(work_event::Event::Opened(e)) => self.handle_opened(e, timestamp),
            Some(work_event::Event::Transitioned(e)) => {
                self.handle_transitioned(e, timestamp, actor_id)
            },
            Some(work_event::Event::Completed(e)) => self.handle_completed(e, timestamp),
            Some(work_event::Event::Aborted(e)) => self.handle_aborted(e, timestamp),
            Some(work_event::Event::PrAssociated(ref e)) => self.handle_pr_associated(e, timestamp),
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
        self.state = WorkReducerState::default();
        self.identity_chain_defects.clear();
    }
}

/// Computes a canonical BLAKE3 hash over length-prefixed variable fields.
///
/// Each field is preceded by its `u32` little-endian length, preventing
/// byte-shifting collisions that arise from raw concatenation of
/// variable-length inputs (e.g., `"ab" || "cd"` vs `"a" || "bcd"`).
///
/// This function is used for defect CAS hashes in both
/// `WorkReducer::record_stale_digest_defect` and
/// `WorkReducer::record_cross_work_injection_defect`, and is also
/// available for use by gate-start defect builders.
#[must_use]
pub fn hash_defect_preimage(field_a: &[u8], field_b: &[u8], field_c: &[u8]) -> [u8; 32] {
    /// Writes a `u32` little-endian length prefix for `data`, saturating at
    /// `u32::MAX` for fields that exceed 4 GiB (which should never occur for
    /// defect preimages, but we never truncate silently).
    fn write_length_prefixed(hasher: &mut blake3::Hasher, data: &[u8]) {
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        hasher.update(&len.to_le_bytes());
        hasher.update(data);
    }

    let mut hasher = blake3::Hasher::new();
    write_length_prefixed(&mut hasher, field_a);
    write_length_prefixed(&mut hasher, field_b);
    write_length_prefixed(&mut hasher, field_c);
    *hasher.finalize().as_bytes()
}

/// Maximum payload size (in bytes) for event payloads before JSON
/// deserialization. Prevents denial-of-service via oversized `SQLite` payloads
/// (up to 1 GiB) exhausting daemon memory during `serde_json::from_slice`.
const MAX_PAYLOAD_BYTES: usize = 1_048_576; // 1 MiB

/// Extracts the `cas_hash` field from a `changeset_published` payload.
///
/// Only called after size validation in `observe_changeset_bound_event`,
/// so the double-parse is limited to `changeset_published` events only.
fn extract_cas_hash_from_payload(payload: &[u8]) -> Option<[u8; 32]> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let cas_hash_value = value.get("cas_hash")?;
    decode_digest_value(cas_hash_value)
}

fn extract_work_id_and_digest_from_payload(payload: &[u8]) -> Option<(String, [u8; 32])> {
    // BLOCKER 1 (Security): Enforce strict max size BEFORE deserialization to
    // prevent DoS via oversized payloads exhausting daemon memory.
    if payload.len() > MAX_PAYLOAD_BYTES {
        warn!(
            payload_size = payload.len(),
            max = MAX_PAYLOAD_BYTES,
            "payload too large for digest extraction, skipping deserialization"
        );
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    find_work_id_and_digest(&value)
}

fn find_work_id_and_digest(value: &serde_json::Value) -> Option<(String, [u8; 32])> {
    match value {
        serde_json::Value::Object(map) => {
            if let (Some(work_id), Some(changeset_value)) = (
                map.get("work_id").and_then(serde_json::Value::as_str),
                map.get("changeset_digest"),
            ) {
                if let Some(digest) = decode_digest_value(changeset_value) {
                    return Some((work_id.to_string(), digest));
                }
            }
            for nested in map.values() {
                if let Some(found) = find_work_id_and_digest(nested) {
                    return Some(found);
                }
            }
            None
        },
        serde_json::Value::Array(items) => {
            for nested in items {
                if let Some(found) = find_work_id_and_digest(nested) {
                    return Some(found);
                }
            }
            None
        },
        _ => None,
    }
}

fn decode_digest_value(value: &serde_json::Value) -> Option<[u8; 32]> {
    match value {
        serde_json::Value::String(hex_value) => {
            let raw = hex::decode(hex_value).ok()?;
            if raw.len() != 32 {
                return None;
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&raw);
            Some(digest)
        },
        serde_json::Value::Array(values) => {
            if values.len() != 32 {
                return None;
            }
            let mut digest = [0u8; 32];
            for (idx, item) in values.iter().enumerate() {
                let byte = u8::try_from(item.as_u64()?).ok()?;
                digest[idx] = byte;
            }
            Some(digest)
        },
        _ => None,
    }
}

/// Helper functions for creating work event payloads.
pub mod helpers {
    use prost::Message;

    use crate::events::{
        WorkAborted, WorkCompleted, WorkEvent, WorkOpened, WorkPrAssociated, WorkTransitioned,
        work_event,
    };

    /// Creates a `WorkOpened` event payload.
    #[must_use]
    pub fn work_opened_payload(
        work_id: &str,
        work_type: &str,
        spec_snapshot_hash: Vec<u8>,
        requirement_ids: Vec<String>,
        parent_work_ids: Vec<String>,
    ) -> Vec<u8> {
        let opened = WorkOpened {
            work_id: work_id.to_string(),
            work_type: work_type.to_string(),
            spec_snapshot_hash,
            requirement_ids,
            parent_work_ids,
        };
        let event = WorkEvent {
            event: Some(work_event::Event::Opened(opened)),
        };
        event.encode_to_vec()
    }

    /// Creates a `WorkTransitioned` event payload for the **first transition
    /// only**.
    ///
    /// This helper sets `previous_transition_count` to 0, which is only valid
    /// for the first transition from the Open state (where `transition_count`
    /// is 0).
    ///
    /// For subsequent transitions, use
    /// [`work_transitioned_payload_with_sequence`] with the work item's
    /// current `transition_count`.
    #[must_use]
    pub fn work_transitioned_payload(
        work_id: &str,
        from_state: &str,
        to_state: &str,
        rationale_code: &str,
    ) -> Vec<u8> {
        work_transitioned_payload_with_sequence(work_id, from_state, to_state, rationale_code, 0)
    }

    /// Creates a `WorkTransitioned` event payload with explicit sequence
    /// validation.
    ///
    /// # Arguments
    ///
    /// * `previous_transition_count` - The expected `transition_count` of the
    ///   work item before this transition. Used for replay protection.
    #[must_use]
    pub fn work_transitioned_payload_with_sequence(
        work_id: &str,
        from_state: &str,
        to_state: &str,
        rationale_code: &str,
        previous_transition_count: u32,
    ) -> Vec<u8> {
        let transitioned = WorkTransitioned {
            work_id: work_id.to_string(),
            from_state: from_state.to_string(),
            to_state: to_state.to_string(),
            rationale_code: rationale_code.to_string(),
            previous_transition_count,
        };
        let event = WorkEvent {
            event: Some(work_event::Event::Transitioned(transitioned)),
        };
        event.encode_to_vec()
    }

    /// Creates a `WorkCompleted` event payload.
    ///
    /// # Parameters
    ///
    /// * `gate_receipt_id` - ID of the gate receipt that authorized this
    ///   completion.  Must NOT contain a merge receipt identifier (values
    ///   starting with `merge-receipt-` are rejected at the reducer level per
    ///   INV-0113).
    /// * `merge_receipt_id` - Dedicated merge receipt identifier populated when
    ///   work completes via the merge executor.  When non-empty, MUST start
    ///   with `merge-receipt-` (positive allowlist per INV-0114).  Pass `""`
    ///   when no merge receipt is involved.
    #[must_use]
    pub fn work_completed_payload(
        work_id: &str,
        evidence_bundle_hash: Vec<u8>,
        evidence_ids: Vec<String>,
        gate_receipt_id: &str,
        merge_receipt_id: &str,
    ) -> Vec<u8> {
        let completed = WorkCompleted {
            work_id: work_id.to_string(),
            evidence_bundle_hash,
            evidence_ids,
            gate_receipt_id: gate_receipt_id.to_string(),
            merge_receipt_id: merge_receipt_id.to_string(),
        };
        let event = WorkEvent {
            event: Some(work_event::Event::Completed(completed)),
        };
        event.encode_to_vec()
    }

    /// Creates a `WorkAborted` event payload.
    #[must_use]
    pub fn work_aborted_payload(
        work_id: &str,
        abort_reason: &str,
        rationale_code: &str,
    ) -> Vec<u8> {
        let aborted = WorkAborted {
            work_id: work_id.to_string(),
            abort_reason: abort_reason.to_string(),
            rationale_code: rationale_code.to_string(),
        };
        let event = WorkEvent {
            event: Some(work_event::Event::Aborted(aborted)),
        };
        event.encode_to_vec()
    }

    /// Creates a `WorkPrAssociated` event payload.
    ///
    /// # CI Gating
    ///
    /// This event associates a PR number with a work item, enabling CI event
    /// matching for phase transitions. Should be emitted when an agent creates
    /// a PR for a work item.
    #[must_use]
    pub fn work_pr_associated_payload(work_id: &str, pr_number: u64, commit_sha: &str) -> Vec<u8> {
        let pr_associated = WorkPrAssociated {
            work_id: work_id.to_string(),
            pr_number,
            commit_sha: commit_sha.to_string(),
        };
        let event = WorkEvent {
            event: Some(work_event::Event::PrAssociated(pr_associated)),
        };
        event.encode_to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_IDENTITY_CHAIN_DEFECTS, MAX_PAYLOAD_BYTES, WorkReducer,
        extract_work_id_and_digest_from_payload, hash_defect_preimage,
    };
    use crate::events::{DefectRecorded, DefectSource};

    #[test]
    fn oversized_payload_returns_none_not_oom() {
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let result = extract_work_id_and_digest_from_payload(&oversized);
        assert!(result.is_none(), "oversized payload must be rejected");
    }

    #[test]
    fn payload_within_limit_is_parsed() {
        let payload = serde_json::to_vec(&serde_json::json!({
            "work_id": "W-1",
            "changeset_digest": hex::encode([0x42; 32]),
        }))
        .expect("serialize");
        assert!(payload.len() <= MAX_PAYLOAD_BYTES);
        let result = extract_work_id_and_digest_from_payload(&payload);
        assert!(result.is_some(), "valid payload should parse");
        let (work_id, digest) = result.unwrap();
        assert_eq!(work_id, "W-1");
        assert_eq!(digest, [0x42; 32]);
    }

    // ---- BLOCKER fix: bounded identity_chain_defects ----

    #[test]
    fn identity_chain_defects_bounded_at_max() {
        let mut reducer = WorkReducer::new();
        let total = MAX_IDENTITY_CHAIN_DEFECTS + 5;

        #[allow(clippy::cast_possible_truncation)]
        for i in 0..total {
            let defect = DefectRecorded {
                defect_id: format!("DEF-{i}"),
                defect_type: "TEST".to_string(),
                cas_hash: vec![(i & 0xFF) as u8],
                source: DefectSource::ProjectionTamper as i32,
                work_id: "W-1".to_string(),
                severity: "S2".to_string(),
                detected_at: i as u64,
                time_envelope_ref: None,
            };
            reducer.push_defect(defect);
        }

        assert_eq!(
            reducer.identity_chain_defect_count(),
            MAX_IDENTITY_CHAIN_DEFECTS,
            "defect buffer must not exceed MAX_IDENTITY_CHAIN_DEFECTS"
        );

        // Oldest entries (0..5) were evicted; first remaining is DEF-5
        let drained = reducer.drain_identity_chain_defects();
        assert_eq!(drained.len(), MAX_IDENTITY_CHAIN_DEFECTS);
        assert_eq!(drained[0].defect_id, "DEF-5");
        assert_eq!(
            drained[MAX_IDENTITY_CHAIN_DEFECTS - 1].defect_id,
            format!("DEF-{}", total - 1)
        );
    }

    #[test]
    fn drain_returns_vec_and_clears_buffer() {
        let mut reducer = WorkReducer::new();
        reducer.push_defect(DefectRecorded {
            defect_id: "DEF-0".to_string(),
            defect_type: "TEST".to_string(),
            cas_hash: vec![0],
            source: DefectSource::ProjectionTamper as i32,
            work_id: "W-1".to_string(),
            severity: "S2".to_string(),
            detected_at: 0,
            time_envelope_ref: None,
        });
        let drained = reducer.drain_identity_chain_defects();
        assert_eq!(drained.len(), 1);
        assert_eq!(reducer.identity_chain_defect_count(), 0);
    }

    // ---- MAJOR fix: canonical length-prefixed hashing ----

    #[test]
    fn hash_defect_preimage_is_collision_resistant() {
        // Without length prefixes, "ab" || "cd" || "" == "a" || "bcd" || ""
        // With length prefixes these MUST differ.
        let h1 = hash_defect_preimage(b"ab", b"cd", b"");
        let h2 = hash_defect_preimage(b"a", b"bcd", b"");
        assert_ne!(
            h1, h2,
            "length-prefixed hashing must prevent byte-shifting collisions"
        );

        // Also verify a second boundary shift.
        let h3 = hash_defect_preimage(b"abc", b"d", b"");
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }

    #[test]
    fn hash_defect_preimage_is_deterministic() {
        let h1 = hash_defect_preimage(b"work-1", &[0xAA; 32], b"reason");
        let h2 = hash_defect_preimage(b"work-1", &[0xAA; 32], b"reason");
        assert_eq!(h1, h2, "same inputs must produce the same hash");
    }
}
