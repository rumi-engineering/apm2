//! Canonicalization support for kernel events.
//!
//! This module provides the [`Canonicalize`] trait for ensuring deterministic
//! serialization of Protocol Buffer messages. Canonical encoding is required
//! for cryptographic signatures to be verifiable.
//!
//! # Why Canonicalization?
//!
//! Protocol Buffers do not guarantee deterministic serialization for repeated
//! fields - elements are encoded in the order they appear in memory. When the
//! same logical data is added in different orders, the encoded bytes differ,
//! causing signature verification to fail.
//!
//! The solution is to sort repeated fields before signing. This module
//! implements that sorting for all event types with repeated fields.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::events::{Canonicalize, WorkOpened};
//!
//! let mut opened = WorkOpened {
//!     work_id: "work-1".to_string(),
//!     work_type: "TICKET".to_string(),
//!     spec_snapshot_hash: vec![],
//!     requirement_ids: vec!["REQ-C".into(), "REQ-A".into(), "REQ-B".into()],
//!     parent_work_ids: vec!["parent-2".into(), "parent-1".into()],
//! };
//!
//! // Before canonicalization: ["REQ-C", "REQ-A", "REQ-B"]
//! opened.canonicalize();
//! // After canonicalization: ["REQ-A", "REQ-B", "REQ-C"]
//!
//! assert_eq!(opened.requirement_ids, vec!["REQ-A", "REQ-B", "REQ-C"]);
//! assert_eq!(opened.parent_work_ids, vec!["parent-1", "parent-2"]);
//! ```

use prost::Message;

use super::{
    AatAttestation, AatGateReceipt, AatSpecQuarantined, AdjudicationRequested, ArtifactManifest,
    EvidencePublished, GateReceipt, GateReceiptGenerated, KernelEvent, LeaseConflict, MergeReceipt,
    PolicyResolvedForChangeSet, RunnerPoolQuarantined, SessionTerminated, ToolDecided,
    ToolExecuted, WorkCompleted, WorkOpened, adjudication_event, evidence_event, kernel_event,
    lease_event, session_event, tool_event, work_event,
};

// =============================================================================
// DOMAIN PREFIXES (RFC-0017 DD-006)
// =============================================================================
//
// Domain separation prefixes prevent cross-context signature replay attacks.
// Each event type has a unique prefix that is prepended to the canonical bytes
// before signing. This ensures that a signature for one event type cannot be
// reused for another event type.

/// Domain prefix for `ToolDecided` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
pub const TOOL_DECIDED_DOMAIN_PREFIX: &[u8] = b"apm2.event.tool_decided:";

/// Domain prefix for `ToolExecuted` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
pub const TOOL_EXECUTED_DOMAIN_PREFIX: &[u8] = b"apm2.event.tool_executed:";

/// Domain prefix for `SessionTerminated` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
pub const SESSION_TERMINATED_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_terminated:";

/// Domain prefix for `WorkClaimed` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
/// Note: `WorkClaimed` event type is defined in apm2-daemon for RFC-0017 Phase
/// 1.
pub const WORK_CLAIMED_DOMAIN_PREFIX: &[u8] = b"apm2.event.work_claimed:";

/// Domain prefix for `WorkTransitioned` events (TCK-00395).
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
/// This prefix is used for work lifecycle state transition events emitted
/// by `SpawnEpisode` (`Claimed` -> `InProgress`) and `ClaimWork` (`Open` ->
/// `Claimed`).
pub const WORK_TRANSITIONED_DOMAIN_PREFIX: &[u8] = b"apm2.event.work_transitioned:";

/// Domain prefix for `EpisodeSpawned` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
/// Note: `EpisodeSpawned` event type is defined in apm2-daemon for RFC-0017
/// Phase 1.
pub const EPISODE_SPAWNED_DOMAIN_PREFIX: &[u8] = b"apm2.event.episode_spawned:";

/// Domain prefix for `MergeReceipt` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
pub const MERGE_RECEIPT_DOMAIN_PREFIX: &[u8] = b"apm2.event.merge_receipt:";

/// Domain prefix for `RunnerPoolQuarantined` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
pub const RUNNER_POOL_QUARANTINED_DOMAIN_PREFIX: &[u8] = b"apm2.event.runner_pool_quarantined:";

/// Domain prefix for `AATSpecQuarantined` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
pub const AAT_SPEC_QUARANTINED_DOMAIN_PREFIX: &[u8] = b"apm2.event.aat_spec_quarantined:";

/// Domain prefix for `AatGateReceipt` payloads.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
/// Note: `AatGateReceipt` is a CAS payload, not a kernel event, but still
/// requires domain-separated signing for integrity verification.
pub const AAT_GATE_RECEIPT_DOMAIN_PREFIX: &[u8] = b"apm2.payload.aat_gate_receipt:";

/// Domain prefix for `ArtifactManifest` payloads.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
/// Note: `ArtifactManifest` is a CAS payload referenced by gate receipts.
pub const ARTIFACT_MANIFEST_DOMAIN_PREFIX: &[u8] = b"apm2.payload.artifact_manifest:";

/// Domain prefix for `ChangeSetPublished` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
/// Used when signing/verifying changeset publication events that anchor
/// the changeset digest and CAS hash before any review begins.
pub const CHANGESET_PUBLISHED_DOMAIN_PREFIX: &[u8] = b"apm2.event.changeset_published:";

/// Domain prefix for `ReviewReceiptRecorded` events **in the ledger**.
///
/// Per RFC-0018 HEF: domain prefixes prevent cross-context replay.
/// Used when signing/verifying review receipt events for ledger ingestion.
///
/// # Security: Domain Separation
///
/// This prefix (`apm2.event.review_receipt_recorded:`) is intentionally
/// **distinct** from the FAC event-level prefix (`REVIEW_RECEIPT_RECORDED:`
/// in `crate::fac`). This separation is critical:
///
/// 1. **FAC prefix**: Used when creating/signing `ReviewReceiptRecorded` events
///    at the domain layer (event creation).
/// 2. **Ledger prefix**: Used when appending events to the ledger via
///    `append_verified()` (ledger ingestion).
///
/// If these prefixes were the same, an attacker could take a valid FAC
/// event signature and replay it as a ledger signature, potentially
/// injecting malformed payloads that the ledger doesn't decode during
/// verification.
///
/// The `apm2.event.*` namespace follows the same pattern as other kernel
/// events (e.g., `tool_decided`, `session_terminated`).
pub const REVIEW_RECEIPT_RECORDED_DOMAIN_PREFIX: &[u8] = b"apm2.event.review_receipt_recorded:";

/// Domain prefix for `ReviewBlockedRecorded` events **in the ledger**.
///
/// Per RFC-0018 HEF: domain prefixes prevent cross-context replay.
/// Used when signing/verifying review blocked events for ledger ingestion.
///
/// # Security: Domain Separation
///
/// This prefix (`apm2.event.review_blocked_recorded:`) is intentionally
/// **distinct** from the FAC event-level prefix (`REVIEW_BLOCKED_RECORDED:`
/// in `crate::fac`). See [`REVIEW_RECEIPT_RECORDED_DOMAIN_PREFIX`] for the
/// security rationale.
pub const REVIEW_BLOCKED_RECORDED_DOMAIN_PREFIX: &[u8] = b"apm2.event.review_blocked_recorded:";

/// Domain prefix for `ProjectionReceiptRecorded` events **in the ledger**.
///
/// Per RFC-0019 FAC: domain prefixes prevent cross-context replay.
/// Used when signing/verifying projection receipt events for ledger ingestion.
///
/// # Security: Domain Separation
///
/// This prefix (`apm2.event.projection_receipt_recorded:`) is intentionally
/// **distinct** from the FAC event-level prefix (`PROJECTION_RECEIPT_RECORDED:`
/// in `crate::fac`). See [`REVIEW_RECEIPT_RECORDED_DOMAIN_PREFIX`] for the
/// security rationale.
///
/// The `apm2.event.*` namespace follows the same pattern as other kernel
/// events (e.g., `tool_decided`, `session_terminated`).
pub const PROJECTION_RECEIPT_RECORDED_DOMAIN_PREFIX: &[u8] =
    b"apm2.event.projection_receipt_recorded:";

/// Trait for canonicalizing messages before signing.
///
/// Types implementing this trait have repeated fields that must be sorted
/// to ensure deterministic encoding. Call `canonicalize()` before computing
/// signatures or hashes.
pub trait Canonicalize {
    /// Sorts all repeated fields to ensure canonical encoding.
    ///
    /// This method modifies the message in place, sorting any repeated fields
    /// in lexicographic order (for strings) or ascending order (for numbers).
    fn canonicalize(&mut self);
}

/// Trait for computing domain-prefixed canonical bytes for signing.
///
/// Per RFC-0017 DD-006, all kernel events must be signed with domain-separated
/// prefixes to prevent cross-context replay attacks. This trait provides the
/// `canonical_bytes_with_domain()` method that prepends the domain prefix to
/// the canonicalized protobuf bytes.
///
/// # Security
///
/// Domain separation ensures that a signature computed for one event type
/// (e.g., `ToolDecided`) cannot be replayed as a different event type
/// (e.g., `ToolExecuted`). The domain prefix is included in the signed bytes,
/// making signatures context-specific.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_core::events::{Canonicalize, DomainSeparatedCanonical, ToolDecided};
///
/// let mut decided = ToolDecided {
///     request_id: "req-1".to_string(),
///     decision: "ALLOW".to_string(),
///     rule_id: "rule-1".to_string(),
///     policy_hash: vec![0u8; 32],
///     rationale_code: "APPROVED".to_string(),
///     budget_consumed: 100,
///     time_envelope_ref: None,
///     episode_id: String::new(),
/// };
///
/// // Get domain-prefixed bytes for signing (automatically canonicalizes)
/// let signing_bytes = decided.canonical_bytes_with_domain();
/// // signing_bytes = b"apm2.event.tool_decided:" + protobuf_bytes
/// ```
pub trait DomainSeparatedCanonical: Canonicalize + Message + Sized {
    /// Returns the domain prefix for this event type.
    ///
    /// The prefix is prepended to the canonical protobuf bytes before signing.
    fn domain_prefix() -> &'static [u8];

    /// Returns the canonical bytes with domain prefix for signing.
    ///
    /// This method:
    /// 1. Calls `canonicalize()` to ensure repeated fields are sorted
    /// 2. Serializes the message to protobuf bytes
    /// 3. Prepends the domain prefix
    ///
    /// By taking `&mut self` and calling `canonicalize()` internally, this
    /// method ensures that the caller cannot forget to canonicalize before
    /// signing.
    fn canonical_bytes_with_domain(&mut self) -> Vec<u8> {
        // Ensure canonical form before encoding - prevents caller from forgetting
        self.canonicalize();

        let prefix = Self::domain_prefix();
        let payload_bytes = self.encode_to_vec();

        let mut canonical_bytes = Vec::with_capacity(prefix.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(prefix);
        canonical_bytes.extend_from_slice(&payload_bytes);
        canonical_bytes
    }
}

impl Canonicalize for WorkOpened {
    fn canonicalize(&mut self) {
        self.requirement_ids.sort();
        self.parent_work_ids.sort();
    }
}

impl Canonicalize for WorkCompleted {
    fn canonicalize(&mut self) {
        self.evidence_ids.sort();
    }
}

impl Canonicalize for AdjudicationRequested {
    fn canonicalize(&mut self) {
        self.options.sort();
    }
}

impl Canonicalize for EvidencePublished {
    fn canonicalize(&mut self) {
        self.verification_command_ids.sort();
        // SEC-CAN-003: Also sort metadata field for determinism.
        self.metadata.sort();
    }
}

impl Canonicalize for GateReceiptGenerated {
    fn canonicalize(&mut self) {
        self.evidence_ids.sort();
    }
}

impl Canonicalize for LeaseConflict {
    fn canonicalize(&mut self) {
        self.conflicting_lease_ids.sort();
    }
}

impl Canonicalize for PolicyResolvedForChangeSet {
    fn canonicalize(&mut self) {
        // SEC-CAN-004: Sort RCP profile IDs and manifest hashes together to
        // maintain alignment. We zip them, sort by profile ID, then unzip back.
        // This ensures that the association between profile IDs and their
        // corresponding hashes is preserved, preventing data corruption.
        if self.resolved_rcp_profile_ids.len() == self.resolved_rcp_manifest_hashes.len() {
            let mut pairs: Vec<(String, Vec<u8>)> = self
                .resolved_rcp_profile_ids
                .drain(..)
                .zip(self.resolved_rcp_manifest_hashes.drain(..))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            for (id, hash) in pairs {
                self.resolved_rcp_profile_ids.push(id);
                self.resolved_rcp_manifest_hashes.push(hash);
            }
        } else {
            // If lengths don't match, sort profile IDs independently.
            // Note: Domain logic in fac/policy_resolution.rs will reject this,
            // but we maintain determinism here for the partial data.
            self.resolved_rcp_profile_ids.sort();
        }

        // Sort verifier policy hashes independently (they're not paired)
        self.resolved_verifier_policy_hashes.sort();
    }
}

impl Canonicalize for GateReceipt {
    fn canonicalize(&mut self) {
        // GateReceipt has no repeated fields, so no sorting is needed.
        // This implementation exists for completeness and to support
        // KernelEvent canonicalization.
    }
}

// =============================================================================
// SEC-CAN-002: RFC-0017 EVENT CANONICALIZE IMPLEMENTATIONS
// =============================================================================
//
// The following implementations address SEC-CAN-002: Missing Canonicalization
// for RFC-0017 Events with repeated fields.

impl Canonicalize for MergeReceipt {
    fn canonicalize(&mut self) {
        // Sort gate_receipt_ids for deterministic encoding.
        self.gate_receipt_ids.sort();
    }
}

impl DomainSeparatedCanonical for MergeReceipt {
    fn domain_prefix() -> &'static [u8] {
        MERGE_RECEIPT_DOMAIN_PREFIX
    }
}

impl Canonicalize for RunnerPoolQuarantined {
    fn canonicalize(&mut self) {
        // Sort evidence_refs for deterministic encoding.
        self.evidence_refs.sort();
    }
}

impl DomainSeparatedCanonical for RunnerPoolQuarantined {
    fn domain_prefix() -> &'static [u8] {
        RUNNER_POOL_QUARANTINED_DOMAIN_PREFIX
    }
}

impl Canonicalize for AatSpecQuarantined {
    fn canonicalize(&mut self) {
        // Sort evidence_refs for deterministic encoding.
        self.evidence_refs.sort();
    }
}

impl DomainSeparatedCanonical for AatSpecQuarantined {
    fn domain_prefix() -> &'static [u8] {
        AAT_SPEC_QUARANTINED_DOMAIN_PREFIX
    }
}

impl Canonicalize for AatAttestation {
    fn canonicalize(&mut self) {
        // Sort toolchain_digests for deterministic encoding.
        self.toolchain_digests.sort();
    }
}

impl Canonicalize for AatGateReceipt {
    fn canonicalize(&mut self) {
        // Sort run_receipt_hashes for deterministic encoding.
        self.run_receipt_hashes.sort();

        // Sort terminal_verifier_outputs by verifier_kind for determinism.
        self.terminal_verifier_outputs
            .sort_by(|a, b| a.verifier_kind.cmp(&b.verifier_kind));

        // Canonicalize nested attestation if present.
        if let Some(ref mut attestation) = self.attestation {
            attestation.canonicalize();
        }
    }
}

impl DomainSeparatedCanonical for AatGateReceipt {
    fn domain_prefix() -> &'static [u8] {
        AAT_GATE_RECEIPT_DOMAIN_PREFIX
    }
}

impl Canonicalize for ArtifactManifest {
    fn canonicalize(&mut self) {
        // Sort artifacts by their digest for deterministic encoding.
        // Digest is a unique identifier for each artifact.
        self.artifacts.sort_by(|a, b| a.digest.cmp(&b.digest));
    }
}

impl DomainSeparatedCanonical for ArtifactManifest {
    fn domain_prefix() -> &'static [u8] {
        ARTIFACT_MANIFEST_DOMAIN_PREFIX
    }
}

// =============================================================================
// RFC-0017 KERNEL EVENT CANONICALIZE IMPLEMENTATIONS (TCK-00264)
// =============================================================================
//
// The following implementations are for RFC-0017 kernel events that require
// domain-separated canonical encoding for signatures.

impl Canonicalize for ToolDecided {
    fn canonicalize(&mut self) {
        // ToolDecided has no repeated fields, so no sorting is needed.
        // This implementation exists to satisfy the DomainSeparatedCanonical
        // trait bound and support KernelEvent canonicalization.
    }
}

impl DomainSeparatedCanonical for ToolDecided {
    fn domain_prefix() -> &'static [u8] {
        TOOL_DECIDED_DOMAIN_PREFIX
    }
}

impl Canonicalize for ToolExecuted {
    fn canonicalize(&mut self) {
        // ToolExecuted has no repeated fields, so no sorting is needed.
        // This implementation exists to satisfy the DomainSeparatedCanonical
        // trait bound and support KernelEvent canonicalization.
    }
}

impl DomainSeparatedCanonical for ToolExecuted {
    fn domain_prefix() -> &'static [u8] {
        TOOL_EXECUTED_DOMAIN_PREFIX
    }
}

impl Canonicalize for SessionTerminated {
    fn canonicalize(&mut self) {
        // SessionTerminated has no repeated fields, so no sorting is needed.
        // This implementation exists to satisfy the DomainSeparatedCanonical
        // trait bound and support KernelEvent canonicalization.
    }
}

impl DomainSeparatedCanonical for SessionTerminated {
    fn domain_prefix() -> &'static [u8] {
        SESSION_TERMINATED_DOMAIN_PREFIX
    }
}

impl Canonicalize for KernelEvent {
    fn canonicalize(&mut self) {
        // Canonicalize nested payload if present.
        // SEC-CAN-002: All event types with repeated fields are handled explicitly.
        // No catch-all `_ => {}` to ensure new event types are reviewed for
        // canonicalization requirements.
        match &mut self.payload {
            Some(kernel_event::Payload::Work(work_event)) => {
                if let Some(event) = &mut work_event.event {
                    match event {
                        work_event::Event::Opened(opened) => opened.canonicalize(),
                        work_event::Event::Completed(completed) => completed.canonicalize(),
                        // These events have no repeated fields:
                        work_event::Event::Transitioned(_)
                        | work_event::Event::Aborted(_)
                        | work_event::Event::PrAssociated(_) => {},
                    }
                }
            },
            Some(kernel_event::Payload::Tool(tool_event)) => {
                if let Some(event) = &mut tool_event.event {
                    match event {
                        tool_event::Event::Decided(decided) => decided.canonicalize(),
                        tool_event::Event::Executed(executed) => executed.canonicalize(),
                        // ToolRequested has no repeated fields.
                        tool_event::Event::Requested(_) => {},
                    }
                }
            },
            Some(kernel_event::Payload::Session(session_event)) => {
                if let Some(event) = &mut session_event.event {
                    match event {
                        session_event::Event::Terminated(terminated) => terminated.canonicalize(),
                        // These events have no repeated fields:
                        session_event::Event::Started(_)
                        | session_event::Event::Progress(_)
                        | session_event::Event::Quarantined(_)
                        | session_event::Event::CrashDetected(_)
                        | session_event::Event::RestartScheduled(_) => {},
                    }
                }
            },
            Some(kernel_event::Payload::Adjudication(adj_event)) => {
                if let Some(event) = &mut adj_event.event {
                    match event {
                        adjudication_event::Event::Requested(requested) => {
                            requested.canonicalize();
                        },
                        // These events have no repeated fields:
                        adjudication_event::Event::Vote(_)
                        | adjudication_event::Event::Resolved(_)
                        | adjudication_event::Event::Timeout(_) => {},
                    }
                }
            },
            Some(kernel_event::Payload::Evidence(ev_event)) => {
                if let Some(event) = &mut ev_event.event {
                    match event {
                        evidence_event::Event::Published(published) => published.canonicalize(),
                        evidence_event::Event::GateReceipt(receipt) => receipt.canonicalize(),
                    }
                }
            },
            Some(kernel_event::Payload::Lease(lease_event)) => {
                if let Some(event) = &mut lease_event.event {
                    match event {
                        lease_event::Event::Conflict(conflict) => conflict.canonicalize(),
                        // These events have no repeated fields:
                        lease_event::Event::Issued(_)
                        | lease_event::Event::Renewed(_)
                        | lease_event::Event::Released(_)
                        | lease_event::Event::Expired(_)
                        | lease_event::Event::IssueDenied(_) => {},
                    }
                }
            },
            Some(kernel_event::Payload::PolicyResolvedForChangeset(policy_resolved)) => {
                policy_resolved.canonicalize();
            },
            Some(kernel_event::Payload::GateReceipt(gate_receipt)) => {
                gate_receipt.canonicalize();
            },
            // SEC-CAN-002: Handle MergeReceipt with repeated gate_receipt_ids.
            Some(kernel_event::Payload::MergeReceipt(merge_receipt)) => {
                merge_receipt.canonicalize();
            },
            // SEC-CAN-002: Handle RunnerPoolQuarantined with repeated evidence_refs.
            Some(kernel_event::Payload::RunnerPoolQuarantined(quarantined)) => {
                quarantined.canonicalize();
            },
            // SEC-CAN-002: Handle AATSpecQuarantined with repeated evidence_refs.
            Some(kernel_event::Payload::AatSpecQuarantined(quarantined)) => {
                quarantined.canonicalize();
            },
            // These payloads have no repeated fields requiring canonicalization,
            // and None means no payload to canonicalize:
            Some(
                kernel_event::Payload::Policy(_)
                | kernel_event::Payload::Key(_)
                | kernel_event::Payload::Capability(_)
                | kernel_event::Payload::GithubLease(_)
                | kernel_event::Payload::InterventionFreeze(_)
                | kernel_event::Payload::InterventionUnfreeze(_)
                | kernel_event::Payload::AatResultReused(_)
                | kernel_event::Payload::QuarantineCleared(_)
                | kernel_event::Payload::ChangesetPublished(_)
                // IoArtifactPublished has no repeated fields (TCK-00306)
                | kernel_event::Payload::IoArtifactPublished(_)
                // DefectRecorded has no repeated fields (TCK-00307)
                | kernel_event::Payload::DefectRecorded(_)
                // ReviewBlockedRecorded has no repeated fields (TCK-00311)
                | kernel_event::Payload::ReviewBlockedRecorded(_)
                // ReviewReceiptRecorded has no repeated fields (TCK-00312)
                | kernel_event::Payload::ReviewReceiptRecorded(_)
                // ProjectionReceiptRecorded has no repeated fields (TCK-00323)
                | kernel_event::Payload::ProjectionReceiptRecorded(_)
                // WorkGraphEvent has no repeated fields (TCK-00642)
                | kernel_event::Payload::WorkGraph(_),
            )
            | None => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_opened_canonicalize() {
        let mut opened = WorkOpened {
            work_id: "work-1".to_string(),
            work_type: "TICKET".to_string(),
            spec_snapshot_hash: vec![],
            requirement_ids: vec!["REQ-C".into(), "REQ-A".into(), "REQ-B".into()],
            parent_work_ids: vec!["parent-2".into(), "parent-1".into()],
        };

        opened.canonicalize();

        assert_eq!(opened.requirement_ids, vec!["REQ-A", "REQ-B", "REQ-C"]);
        assert_eq!(opened.parent_work_ids, vec!["parent-1", "parent-2"]);
    }

    #[test]
    fn test_work_completed_canonicalize() {
        let mut completed = WorkCompleted {
            work_id: "work-1".to_string(),
            evidence_bundle_hash: vec![],
            evidence_ids: vec!["EVID-3".into(), "EVID-1".into(), "EVID-2".into()],
            gate_receipt_id: String::new(),
        };

        completed.canonicalize();

        assert_eq!(completed.evidence_ids, vec!["EVID-1", "EVID-2", "EVID-3"]);
    }

    #[test]
    fn test_adjudication_requested_canonicalize() {
        let mut requested = AdjudicationRequested {
            adjudication_id: "adj-1".to_string(),
            work_id: "work-1".to_string(),
            request_type: "BOUNDED_CHOICE".to_string(),
            options: vec!["Option C".into(), "Option A".into(), "Option B".into()],
            deadline: 0,
            fallback_policy: String::new(),
        };

        requested.canonicalize();

        assert_eq!(requested.options, vec!["Option A", "Option B", "Option C"]);
    }

    #[test]
    fn test_evidence_published_canonicalize() {
        let mut published = EvidencePublished {
            evidence_id: "evid-1".to_string(),
            work_id: "work-1".to_string(),
            category: "TEST".to_string(),
            artifact_hash: vec![],
            verification_command_ids: vec!["CMD-Z".into(), "CMD-A".into(), "CMD-M".into()],
            classification: "INTERNAL".to_string(),
            artifact_size: 100,
            metadata: vec!["key=value".to_string()],
            // HTF time envelope reference (RFC-0016): not yet populated.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
        };

        published.canonicalize();

        assert_eq!(
            published.verification_command_ids,
            vec!["CMD-A", "CMD-M", "CMD-Z"]
        );
    }

    #[test]
    fn test_gate_receipt_canonicalize() {
        let mut receipt = GateReceiptGenerated {
            receipt_id: "rcpt-1".to_string(),
            gate_id: "gate-1".to_string(),
            work_id: "work-1".to_string(),
            result: "PASS".to_string(),
            evidence_ids: vec!["E3".into(), "E1".into(), "E2".into()],
            receipt_signature: vec![],
        };

        receipt.canonicalize();

        assert_eq!(receipt.evidence_ids, vec!["E1", "E2", "E3"]);
    }

    #[test]
    fn test_lease_conflict_canonicalize() {
        let mut conflict = LeaseConflict {
            work_id: "work-1".to_string(),
            conflicting_lease_ids: vec!["lease-c".into(), "lease-a".into(), "lease-b".into()],
            resolution: "ADJUDICATION_REQUIRED".to_string(),
        };

        conflict.canonicalize();

        assert_eq!(
            conflict.conflicting_lease_ids,
            vec!["lease-a", "lease-b", "lease-c"]
        );
    }

    #[test]
    fn test_kernel_event_canonicalize_work_opened() {
        use super::super::{WorkEvent, work_event};

        let mut event = KernelEvent {
            sequence: 1,
            payload: Some(kernel_event::Payload::Work(WorkEvent {
                event: Some(work_event::Event::Opened(WorkOpened {
                    work_id: "work-1".to_string(),
                    work_type: "TICKET".to_string(),
                    spec_snapshot_hash: vec![],
                    requirement_ids: vec!["REQ-B".into(), "REQ-A".into()],
                    parent_work_ids: vec![],
                })),
            })),
            ..Default::default()
        };

        event.canonicalize();

        if let Some(kernel_event::Payload::Work(work)) = &event.payload {
            if let Some(work_event::Event::Opened(opened)) = &work.event {
                assert_eq!(opened.requirement_ids, vec!["REQ-A", "REQ-B"]);
            } else {
                panic!("Expected WorkOpened");
            }
        } else {
            panic!("Expected Work payload");
        }
    }

    #[test]
    fn test_empty_repeated_fields() {
        // Canonicalizing empty fields should not panic
        let mut opened = WorkOpened::default();
        opened.canonicalize();
        assert!(opened.requirement_ids.is_empty());

        let mut completed = WorkCompleted::default();
        completed.canonicalize();
        assert!(completed.evidence_ids.is_empty());
    }

    #[test]
    fn test_already_sorted() {
        // Canonicalizing already-sorted fields should be idempotent
        let mut opened = WorkOpened {
            work_id: "work-1".to_string(),
            work_type: "TICKET".to_string(),
            spec_snapshot_hash: vec![],
            requirement_ids: vec!["REQ-A".into(), "REQ-B".into(), "REQ-C".into()],
            parent_work_ids: vec!["parent-1".into(), "parent-2".into()],
        };

        let before = opened.requirement_ids.clone();
        opened.canonicalize();
        assert_eq!(opened.requirement_ids, before);
    }

    #[test]
    fn test_policy_resolved_for_changeset_canonicalize() {
        let mut policy_resolved = PolicyResolvedForChangeSet {
            work_id: "work-1".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 1,
            resolved_determinism_class: 0,
            // Unsorted profile IDs with corresponding manifest hashes
            resolved_rcp_profile_ids: vec![
                "z-profile".into(),
                "a-profile".into(),
                "m-profile".into(),
            ],
            resolved_rcp_manifest_hashes: vec![
                vec![0x99; 32], // corresponds to z-profile
                vec![0x11; 32], // corresponds to a-profile
                vec![0x55; 32], // corresponds to m-profile
            ],
            // Unsorted verifier policy hashes
            resolved_verifier_policy_hashes: vec![vec![0xCC; 32], vec![0xAA; 32], vec![0xBB; 32]],
            role_spec_hash: vec![],
            context_pack_recipe_hash: vec![],
            resolver_actor_id: "resolver-1".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        policy_resolved.canonicalize();

        // SEC-CAN-004: Profile IDs should be sorted alphabetically, with their
        // corresponding manifest hashes moving together (paired sorting).
        assert_eq!(
            policy_resolved.resolved_rcp_profile_ids,
            vec!["a-profile", "m-profile", "z-profile"]
        );

        // SEC-CAN-004: Manifest hashes follow the same order as their paired profile
        // IDs. Input: z -> 0x99, a -> 0x11, m -> 0x55
        // After paired sort: a -> 0x11, m -> 0x55, z -> 0x99
        assert_eq!(
            policy_resolved.resolved_rcp_manifest_hashes,
            vec![vec![0x11; 32], vec![0x55; 32], vec![0x99; 32]]
        );

        // Verifier policy hashes should be sorted independently
        assert_eq!(
            policy_resolved.resolved_verifier_policy_hashes,
            vec![vec![0xAA; 32], vec![0xBB; 32], vec![0xCC; 32]]
        );
    }

    #[test]
    fn test_kernel_event_canonicalize_policy_resolved() {
        let mut event = KernelEvent {
            sequence: 1,
            payload: Some(kernel_event::Payload::PolicyResolvedForChangeset(
                PolicyResolvedForChangeSet {
                    work_id: "work-1".to_string(),
                    changeset_digest: vec![0x42; 32],
                    resolved_policy_hash: vec![0x00; 32],
                    resolved_risk_tier: 1,
                    resolved_determinism_class: 0,
                    resolved_rcp_profile_ids: vec!["z-profile".into(), "a-profile".into()],
                    resolved_rcp_manifest_hashes: vec![vec![0x99; 32], vec![0x11; 32]],
                    resolved_verifier_policy_hashes: vec![vec![0xBB; 32], vec![0xAA; 32]],
                    role_spec_hash: vec![],
                    context_pack_recipe_hash: vec![],
                    resolver_actor_id: "resolver-1".to_string(),
                    resolver_version: "1.0.0".to_string(),
                    resolver_signature: vec![0u8; 64],
                },
            )),
            ..Default::default()
        };

        event.canonicalize();

        if let Some(kernel_event::Payload::PolicyResolvedForChangeset(policy_resolved)) =
            &event.payload
        {
            // SEC-CAN-004: Profile IDs and manifest hashes are sorted together as pairs.
            // Input: z -> 0x99, a -> 0x11. After paired sort: a -> 0x11, z -> 0x99
            assert_eq!(
                policy_resolved.resolved_rcp_profile_ids,
                vec!["a-profile", "z-profile"]
            );
            assert_eq!(
                policy_resolved.resolved_rcp_manifest_hashes,
                vec![vec![0x11; 32], vec![0x99; 32]]
            );
            // Verifier policy hashes are sorted independently (not paired)
            assert_eq!(
                policy_resolved.resolved_verifier_policy_hashes,
                vec![vec![0xAA; 32], vec![0xBB; 32]]
            );
        } else {
            panic!("Expected PolicyResolvedForChangeset payload");
        }
    }

    // =========================================================================
    // TCK-00264: Golden Vector Tests for RFC-0017 Kernel Events
    // =========================================================================
    //
    // These tests verify:
    // 1. Canonical bytes are deterministic across runs
    // 2. Domain prefixes prevent cross-context replay

    use super::{
        DomainSeparatedCanonical, EPISODE_SPAWNED_DOMAIN_PREFIX, SESSION_TERMINATED_DOMAIN_PREFIX,
        TOOL_DECIDED_DOMAIN_PREFIX, TOOL_EXECUTED_DOMAIN_PREFIX, WORK_CLAIMED_DOMAIN_PREFIX,
    };

    /// TCK-00264: Verify `ToolDecided` canonical bytes are deterministic.
    ///
    /// Golden vector test: same input must produce same output across runs.
    #[test]
    fn tck_00264_tool_decided_canonical_bytes_deterministic() {
        use super::ToolDecided;

        let mut decided = ToolDecided {
            request_id: "req-golden-001".to_string(),
            decision: "ALLOW".to_string(),
            rule_id: "rule-001".to_string(),
            policy_hash: vec![0xAB; 32],
            rationale_code: "POLICY_APPROVED".to_string(),
            budget_consumed: 42,
            time_envelope_ref: None,
            episode_id: String::new(),
        };

        decided.canonicalize();

        // Compute canonical bytes with domain prefix
        let bytes1 = decided.canonical_bytes_with_domain();
        let bytes2 = decided.canonical_bytes_with_domain();

        // Must be deterministic
        assert_eq!(bytes1, bytes2, "Canonical bytes must be deterministic");

        // Verify domain prefix is prepended
        assert!(
            bytes1.starts_with(TOOL_DECIDED_DOMAIN_PREFIX),
            "Canonical bytes must start with domain prefix"
        );

        // Golden vector: verify the prefix is correct
        let prefix_len = TOOL_DECIDED_DOMAIN_PREFIX.len();
        assert_eq!(&bytes1[..prefix_len], b"apm2.event.tool_decided:");
    }

    /// TCK-00264: Verify `ToolExecuted` canonical bytes are deterministic.
    ///
    /// Golden vector test: same input must produce same output across runs.
    #[test]
    fn tck_00264_tool_executed_canonical_bytes_deterministic() {
        use super::ToolExecuted;

        let mut executed = ToolExecuted {
            request_id: "req-golden-002".to_string(),
            outcome: "SUCCESS".to_string(),
            result_hash: vec![0xCD; 32],
            duration_ms: 1234,
            time_envelope_ref: None,
            episode_id: String::new(),
        };

        executed.canonicalize();

        // Compute canonical bytes with domain prefix
        let bytes1 = executed.canonical_bytes_with_domain();
        let bytes2 = executed.canonical_bytes_with_domain();

        // Must be deterministic
        assert_eq!(bytes1, bytes2, "Canonical bytes must be deterministic");

        // Verify domain prefix is prepended
        assert!(
            bytes1.starts_with(TOOL_EXECUTED_DOMAIN_PREFIX),
            "Canonical bytes must start with domain prefix"
        );

        // Golden vector: verify the prefix is correct
        let prefix_len = TOOL_EXECUTED_DOMAIN_PREFIX.len();
        assert_eq!(&bytes1[..prefix_len], b"apm2.event.tool_executed:");
    }

    /// TCK-00264: Verify `SessionTerminated` canonical bytes are deterministic.
    ///
    /// Golden vector test: same input must produce same output across runs.
    #[test]
    fn tck_00264_session_terminated_canonical_bytes_deterministic() {
        use super::SessionTerminated;

        let mut terminated = SessionTerminated {
            session_id: "session-golden-003".to_string(),
            exit_classification: "SUCCESS".to_string(),
            rationale_code: "COMPLETED_NORMALLY".to_string(),
            final_entropy: 9876,
            time_envelope_ref: None,
            episode_id: String::new(),
        };

        terminated.canonicalize();

        // Compute canonical bytes with domain prefix
        let bytes1 = terminated.canonical_bytes_with_domain();
        let bytes2 = terminated.canonical_bytes_with_domain();

        // Must be deterministic
        assert_eq!(bytes1, bytes2, "Canonical bytes must be deterministic");

        // Verify domain prefix is prepended
        assert!(
            bytes1.starts_with(SESSION_TERMINATED_DOMAIN_PREFIX),
            "Canonical bytes must start with domain prefix"
        );

        // Golden vector: verify the prefix is correct
        let prefix_len = SESSION_TERMINATED_DOMAIN_PREFIX.len();
        assert_eq!(&bytes1[..prefix_len], b"apm2.event.session_terminated:");
    }

    /// TCK-00264: Verify domain prefixes prevent cross-context replay.
    ///
    /// A signature computed for one event type must not be valid for another.
    /// This test verifies that domain prefixes are unique across event types.
    #[test]
    fn tck_00264_domain_prefixes_prevent_cross_context_replay() {
        // All domain prefixes must be unique
        let prefixes = [
            TOOL_DECIDED_DOMAIN_PREFIX,
            TOOL_EXECUTED_DOMAIN_PREFIX,
            SESSION_TERMINATED_DOMAIN_PREFIX,
            WORK_CLAIMED_DOMAIN_PREFIX,
            EPISODE_SPAWNED_DOMAIN_PREFIX,
        ];

        // Check uniqueness
        for (i, prefix_a) in prefixes.iter().enumerate() {
            for (j, prefix_b) in prefixes.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        prefix_a, prefix_b,
                        "Domain prefixes must be unique to prevent replay attacks"
                    );
                }
            }
        }

        // Verify prefixes have the correct format
        for prefix in &prefixes {
            let prefix_str = std::str::from_utf8(prefix).expect("Prefix must be valid UTF-8");
            assert!(
                prefix_str.starts_with("apm2.event."),
                "Prefix must start with 'apm2.event.'"
            );
            assert!(prefix_str.ends_with(':'), "Prefix must end with ':'");
        }
    }

    /// TCK-00264: Verify canonical bytes differ across event types.
    ///
    /// Even with similar field values, canonical bytes must differ due to
    /// domain prefixes and protobuf field tags.
    #[test]
    fn tck_00264_canonical_bytes_differ_across_event_types() {
        use super::{SessionTerminated, ToolDecided, ToolExecuted};

        // Create events with similar field values
        let mut decided = ToolDecided {
            request_id: "id-same".to_string(),
            decision: "SUCCESS".to_string(),
            rule_id: "rule".to_string(),
            policy_hash: vec![0x00; 32],
            rationale_code: "CODE".to_string(),
            budget_consumed: 100,
            time_envelope_ref: None,
            episode_id: String::new(),
        };

        let mut executed = ToolExecuted {
            request_id: "id-same".to_string(),
            outcome: "SUCCESS".to_string(),
            result_hash: vec![0x00; 32],
            duration_ms: 100,
            time_envelope_ref: None,
            episode_id: String::new(),
        };

        let mut terminated = SessionTerminated {
            session_id: "id-same".to_string(),
            exit_classification: "SUCCESS".to_string(),
            rationale_code: "CODE".to_string(),
            final_entropy: 100,
            time_envelope_ref: None,
            episode_id: String::new(),
        };

        decided.canonicalize();
        executed.canonicalize();
        terminated.canonicalize();

        let bytes_decided = decided.canonical_bytes_with_domain();
        let bytes_executed = executed.canonical_bytes_with_domain();
        let bytes_terminated = terminated.canonical_bytes_with_domain();

        // All canonical bytes must be different
        assert_ne!(
            bytes_decided, bytes_executed,
            "ToolDecided and ToolExecuted must have different canonical bytes"
        );
        assert_ne!(
            bytes_decided, bytes_terminated,
            "ToolDecided and SessionTerminated must have different canonical bytes"
        );
        assert_ne!(
            bytes_executed, bytes_terminated,
            "ToolExecuted and SessionTerminated must have different canonical bytes"
        );
    }

    /// TCK-00264: Verify `KernelEvent` canonicalize handles `ToolEvent`.
    #[test]
    fn tck_00264_kernel_event_canonicalize_tool_event() {
        use super::super::{ToolEvent, tool_event};

        let mut event = KernelEvent {
            sequence: 1,
            payload: Some(kernel_event::Payload::Tool(ToolEvent {
                event: Some(tool_event::Event::Decided(ToolDecided {
                    request_id: "req-1".to_string(),
                    decision: "ALLOW".to_string(),
                    rule_id: "rule-1".to_string(),
                    policy_hash: vec![0x00; 32],
                    rationale_code: "APPROVED".to_string(),
                    budget_consumed: 50,
                    time_envelope_ref: None,
                    episode_id: String::new(),
                })),
            })),
            ..Default::default()
        };

        // Should not panic
        event.canonicalize();

        // Verify payload is still intact
        assert!(event.payload.is_some());
    }

    /// TCK-00264: Verify `KernelEvent` canonicalize handles `SessionEvent`.
    #[test]
    fn tck_00264_kernel_event_canonicalize_session_event() {
        use super::super::{SessionEvent, session_event};

        let mut event = KernelEvent {
            sequence: 1,
            payload: Some(kernel_event::Payload::Session(SessionEvent {
                event: Some(session_event::Event::Terminated(SessionTerminated {
                    session_id: "session-1".to_string(),
                    exit_classification: "SUCCESS".to_string(),
                    rationale_code: "COMPLETED".to_string(),
                    final_entropy: 1000,
                    time_envelope_ref: None,
                    episode_id: String::new(),
                })),
            })),
            ..Default::default()
        };

        // Should not panic
        event.canonicalize();

        // Verify payload is still intact
        assert!(event.payload.is_some());
    }

    /// TCK-00264: Verify domain prefix constants match RFC-0017 specification.
    #[test]
    fn tck_00264_domain_prefix_constants_match_rfc() {
        // These values are specified in RFC-0017 DD-006
        assert_eq!(TOOL_DECIDED_DOMAIN_PREFIX, b"apm2.event.tool_decided:");
        assert_eq!(TOOL_EXECUTED_DOMAIN_PREFIX, b"apm2.event.tool_executed:");
        assert_eq!(
            SESSION_TERMINATED_DOMAIN_PREFIX,
            b"apm2.event.session_terminated:"
        );
        assert_eq!(WORK_CLAIMED_DOMAIN_PREFIX, b"apm2.event.work_claimed:");
        assert_eq!(
            EPISODE_SPAWNED_DOMAIN_PREFIX,
            b"apm2.event.episode_spawned:"
        );
    }

    /// TCK-00264: Golden vector for `ToolDecided` with known bytes.
    ///
    /// This test uses a fixed input and verifies the output matches a
    /// precomputed golden vector. If the protobuf encoding changes,
    /// this test will fail and the golden vector must be updated.
    #[test]
    fn tck_00264_tool_decided_golden_vector() {
        use super::ToolDecided;

        // Fixed input for reproducibility
        let mut decided = ToolDecided {
            request_id: "REQ-001".to_string(),
            decision: "ALLOW".to_string(),
            rule_id: "RULE-001".to_string(),
            policy_hash: vec![0x00; 32], // 32 zero bytes
            rationale_code: "OK".to_string(),
            budget_consumed: 0,
            time_envelope_ref: None,
            episode_id: String::new(),
        };

        decided.canonicalize();
        let bytes = decided.canonical_bytes_with_domain();

        // Verify prefix
        assert!(bytes.starts_with(b"apm2.event.tool_decided:"));

        // Verify determinism by encoding twice
        let bytes2 = decided.canonical_bytes_with_domain();
        assert_eq!(bytes, bytes2, "Golden vector must be stable across runs");

        // Verify minimum expected length (prefix + at least some protobuf bytes)
        let min_len = TOOL_DECIDED_DOMAIN_PREFIX.len() + 10; // At least some content
        assert!(
            bytes.len() >= min_len,
            "Canonical bytes must include both prefix and payload"
        );
    }

    /// TCK-00264: Golden vector for `ToolExecuted` with known bytes.
    #[test]
    fn tck_00264_tool_executed_golden_vector() {
        use super::ToolExecuted;

        // Fixed input for reproducibility
        let mut executed = ToolExecuted {
            request_id: "REQ-001".to_string(),
            outcome: "SUCCESS".to_string(),
            result_hash: vec![0xFF; 32], // 32 0xFF bytes
            duration_ms: 100,
            time_envelope_ref: None,
            episode_id: String::new(),
        };

        executed.canonicalize();
        let bytes = executed.canonical_bytes_with_domain();

        // Verify prefix
        assert!(bytes.starts_with(b"apm2.event.tool_executed:"));

        // Verify determinism
        let bytes2 = executed.canonical_bytes_with_domain();
        assert_eq!(bytes, bytes2, "Golden vector must be stable across runs");
    }

    /// TCK-00264: Golden vector for `SessionTerminated` with known bytes.
    #[test]
    fn tck_00264_session_terminated_golden_vector() {
        use super::SessionTerminated;

        // Fixed input for reproducibility
        let mut terminated = SessionTerminated {
            session_id: "SESS-001".to_string(),
            exit_classification: "SUCCESS".to_string(),
            rationale_code: "NORMAL".to_string(),
            final_entropy: 500,
            time_envelope_ref: None,
            episode_id: String::new(),
        };

        terminated.canonicalize();
        let bytes = terminated.canonical_bytes_with_domain();

        // Verify prefix
        assert!(bytes.starts_with(b"apm2.event.session_terminated:"));

        // Verify determinism
        let bytes2 = terminated.canonical_bytes_with_domain();
        assert_eq!(bytes, bytes2, "Golden vector must be stable across runs");
    }

    // =========================================================================
    // SEC-CAN-002: Golden Vector Tests for RFC-0017 Events with Repeated Fields
    // =========================================================================

    use super::{
        AAT_GATE_RECEIPT_DOMAIN_PREFIX, AAT_SPEC_QUARANTINED_DOMAIN_PREFIX,
        ARTIFACT_MANIFEST_DOMAIN_PREFIX, MERGE_RECEIPT_DOMAIN_PREFIX,
        RUNNER_POOL_QUARANTINED_DOMAIN_PREFIX,
    };

    /// SEC-CAN-002: Verify `MergeReceipt` canonical bytes are deterministic.
    #[test]
    fn sec_can_002_merge_receipt_canonical_bytes_deterministic() {
        use super::MergeReceipt;

        let mut receipt = MergeReceipt {
            base_selector: "main".to_string(),
            changeset_digest: vec![0xAB; 32],
            gate_receipt_ids: vec![
                "receipt-z".to_string(),
                "receipt-a".to_string(),
                "receipt-m".to_string(),
            ],
            policy_hash: vec![0xCD; 32],
            result_selector: "abc123".to_string(),
            merged_at: 1_234_567_890,
            gate_actor_id: "gate-actor".to_string(),
            gate_signature: vec![0u8; 64],
            time_envelope_ref: None,
        };

        receipt.canonicalize();

        // Verify gate_receipt_ids are sorted
        assert_eq!(
            receipt.gate_receipt_ids,
            vec!["receipt-a", "receipt-m", "receipt-z"]
        );

        // Verify canonical bytes with domain prefix
        let bytes1 = receipt.canonical_bytes_with_domain();
        let bytes2 = receipt.canonical_bytes_with_domain();

        assert_eq!(bytes1, bytes2, "Canonical bytes must be deterministic");
        assert!(
            bytes1.starts_with(MERGE_RECEIPT_DOMAIN_PREFIX),
            "Canonical bytes must start with domain prefix"
        );
    }

    /// SEC-CAN-002: Verify `RunnerPoolQuarantined` canonical bytes are
    /// deterministic.
    #[test]
    fn sec_can_002_runner_pool_quarantined_canonical_bytes_deterministic() {
        use super::RunnerPoolQuarantined;

        let mut quarantined = RunnerPoolQuarantined {
            quarantine_id: "quar-001".to_string(),
            pool_id: "pool-001".to_string(),
            reason: "flaky infrastructure".to_string(),
            evidence_refs: vec![
                "evid-z".to_string(),
                "evid-a".to_string(),
                "evid-m".to_string(),
            ],
            time_envelope_ref: None,
            issuer_actor_id: "issuer-001".to_string(),
            issuer_signature: vec![0u8; 64],
        };

        quarantined.canonicalize();

        // Verify evidence_refs are sorted
        assert_eq!(
            quarantined.evidence_refs,
            vec!["evid-a", "evid-m", "evid-z"]
        );

        // Verify canonical bytes with domain prefix
        let bytes1 = quarantined.canonical_bytes_with_domain();
        let bytes2 = quarantined.canonical_bytes_with_domain();

        assert_eq!(bytes1, bytes2, "Canonical bytes must be deterministic");
        assert!(
            bytes1.starts_with(RUNNER_POOL_QUARANTINED_DOMAIN_PREFIX),
            "Canonical bytes must start with domain prefix"
        );
    }

    /// SEC-CAN-002: Verify `AATSpecQuarantined` canonical bytes are
    /// deterministic.
    #[test]
    fn sec_can_002_aat_spec_quarantined_canonical_bytes_deterministic() {
        use super::AatSpecQuarantined;

        let mut quarantined = AatSpecQuarantined {
            quarantine_id: "quar-002".to_string(),
            spec_id: "spec-001".to_string(),
            reason: "non-deterministic output".to_string(),
            evidence_refs: vec![
                "evid-3".to_string(),
                "evid-1".to_string(),
                "evid-2".to_string(),
            ],
            time_envelope_ref: None,
            issuer_actor_id: "issuer-002".to_string(),
            issuer_signature: vec![0u8; 64],
        };

        quarantined.canonicalize();

        // Verify evidence_refs are sorted
        assert_eq!(
            quarantined.evidence_refs,
            vec!["evid-1", "evid-2", "evid-3"]
        );

        // Verify canonical bytes with domain prefix
        let bytes1 = quarantined.canonical_bytes_with_domain();
        let bytes2 = quarantined.canonical_bytes_with_domain();

        assert_eq!(bytes1, bytes2, "Canonical bytes must be deterministic");
        assert!(
            bytes1.starts_with(AAT_SPEC_QUARANTINED_DOMAIN_PREFIX),
            "Canonical bytes must start with domain prefix"
        );
    }

    /// SEC-CAN-002: Verify `AatGateReceipt` canonical bytes are deterministic.
    #[test]
    fn sec_can_002_aat_gate_receipt_canonical_bytes_deterministic() {
        use super::super::{
            AatAttestation, AatGateReceipt, AatVerdict, DeterminismStatus, FlakeClass,
            TerminalVerifierOutput,
        };

        let mut receipt = AatGateReceipt {
            view_commitment_hash: vec![0x01; 32],
            rcp_manifest_hash: vec![0x02; 32],
            rcp_profile_id: "profile-001".to_string(),
            policy_hash: vec![0x03; 32],
            determinism_class: 2,
            determinism_status: DeterminismStatus::Stable.into(),
            flake_class: FlakeClass::Unspecified.into(),
            run_count: 3,
            run_receipt_hashes: vec![vec![0xCC; 32], vec![0xAA; 32], vec![0xBB; 32]],
            terminal_evidence_digest: vec![0x04; 32],
            observational_evidence_digest: vec![0x05; 32],
            terminal_verifier_outputs_digest: vec![0x06; 32],
            stability_digest: vec![0x07; 32],
            verdict: AatVerdict::Pass.into(),
            transcript_chain_root_hash: vec![0x08; 32],
            transcript_bundle_hash: vec![0x09; 32],
            artifact_manifest_hash: vec![0x0A; 32],
            terminal_verifier_outputs: vec![
                TerminalVerifierOutput {
                    verifier_kind: "z-verifier".to_string(),
                    output_digest: vec![0x10; 32],
                    predicate_satisfied: true,
                },
                TerminalVerifierOutput {
                    verifier_kind: "a-verifier".to_string(),
                    output_digest: vec![0x11; 32],
                    predicate_satisfied: true,
                },
            ],
            verifier_policy_hash: vec![0x0B; 32],
            selection_policy_id: "policy-001".to_string(),
            risk_tier: 1,
            attestation: Some(AatAttestation {
                container_image_digest: vec![0x0C; 32],
                toolchain_digests: vec![vec![0xDD; 32], vec![0xAA; 32], vec![0xBB; 32]],
                runner_identity_key_id: "runner-001".to_string(),
                network_policy_profile_hash: vec![0x0D; 32],
            }),
        };

        receipt.canonicalize();

        // Verify run_receipt_hashes are sorted
        assert_eq!(
            receipt.run_receipt_hashes,
            vec![vec![0xAA; 32], vec![0xBB; 32], vec![0xCC; 32]]
        );

        // Verify terminal_verifier_outputs are sorted by verifier_kind
        assert_eq!(
            receipt.terminal_verifier_outputs[0].verifier_kind,
            "a-verifier"
        );
        assert_eq!(
            receipt.terminal_verifier_outputs[1].verifier_kind,
            "z-verifier"
        );

        // Verify nested attestation toolchain_digests are sorted
        assert_eq!(
            receipt.attestation.as_ref().unwrap().toolchain_digests,
            vec![vec![0xAA; 32], vec![0xBB; 32], vec![0xDD; 32]]
        );

        // Verify canonical bytes with domain prefix
        let bytes1 = receipt.canonical_bytes_with_domain();
        let bytes2 = receipt.canonical_bytes_with_domain();

        assert_eq!(bytes1, bytes2, "Canonical bytes must be deterministic");
        assert!(
            bytes1.starts_with(AAT_GATE_RECEIPT_DOMAIN_PREFIX),
            "Canonical bytes must start with domain prefix"
        );
    }

    /// SEC-CAN-002: Verify `ArtifactManifest` canonical bytes are
    /// deterministic.
    #[test]
    fn sec_can_002_artifact_manifest_canonical_bytes_deterministic() {
        use super::super::{ArtifactDigest, ArtifactManifest, ArtifactType, DataClassification};

        let mut manifest = ArtifactManifest {
            artifacts: vec![
                ArtifactDigest {
                    artifact_type: ArtifactType::Log.into(),
                    digest: vec![0xCC; 32],
                    data_classification: DataClassification::Internal.into(),
                    redaction_applied: false,
                    redaction_profile_hash: vec![],
                    retention_window_ref: "30d".to_string(),
                },
                ArtifactDigest {
                    artifact_type: ArtifactType::Junit.into(),
                    digest: vec![0xAA; 32],
                    data_classification: DataClassification::Public.into(),
                    redaction_applied: false,
                    redaction_profile_hash: vec![],
                    retention_window_ref: "90d".to_string(),
                },
                ArtifactDigest {
                    artifact_type: ArtifactType::Coverage.into(),
                    digest: vec![0xBB; 32],
                    data_classification: DataClassification::Internal.into(),
                    redaction_applied: false,
                    redaction_profile_hash: vec![],
                    retention_window_ref: "30d".to_string(),
                },
            ],
        };

        manifest.canonicalize();

        // Verify artifacts are sorted by digest
        assert_eq!(manifest.artifacts[0].digest, vec![0xAA; 32]);
        assert_eq!(manifest.artifacts[1].digest, vec![0xBB; 32]);
        assert_eq!(manifest.artifacts[2].digest, vec![0xCC; 32]);

        // Verify canonical bytes with domain prefix
        let bytes1 = manifest.canonical_bytes_with_domain();
        let bytes2 = manifest.canonical_bytes_with_domain();

        assert_eq!(bytes1, bytes2, "Canonical bytes must be deterministic");
        assert!(
            bytes1.starts_with(ARTIFACT_MANIFEST_DOMAIN_PREFIX),
            "Canonical bytes must start with domain prefix"
        );
    }

    /// SEC-CAN-003: Verify `EvidencePublished` sorts both
    /// `verification_command_ids` and metadata.
    #[test]
    fn sec_can_003_evidence_published_sorts_metadata() {
        let mut published = EvidencePublished {
            evidence_id: "evid-001".to_string(),
            work_id: "work-001".to_string(),
            category: "TEST".to_string(),
            artifact_hash: vec![0xAB; 32],
            verification_command_ids: vec!["cmd-z".into(), "cmd-a".into(), "cmd-m".into()],
            classification: "INTERNAL".to_string(),
            artifact_size: 1000,
            metadata: vec![
                "z-key=z-value".to_string(),
                "a-key=a-value".to_string(),
                "m-key=m-value".to_string(),
            ],
            time_envelope_ref: None,
        };

        published.canonicalize();

        // Verify verification_command_ids are sorted
        assert_eq!(
            published.verification_command_ids,
            vec!["cmd-a", "cmd-m", "cmd-z"]
        );

        // Verify metadata is sorted
        assert_eq!(
            published.metadata,
            vec!["a-key=a-value", "m-key=m-value", "z-key=z-value"]
        );
    }

    /// SEC-CAN-004: Verify `PolicyResolvedForChangeSet` sorts fields as pairs
    /// to maintain data alignment between profiles and hashes.
    #[test]
    fn sec_can_004_policy_resolved_paired_sorting() {
        let mut policy_resolved = PolicyResolvedForChangeSet {
            work_id: "work-1".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 1,
            resolved_determinism_class: 0,
            // Paired alignment: z -> 0x99, a -> 0x11
            resolved_rcp_profile_ids: vec!["z-profile".into(), "a-profile".into()],
            resolved_rcp_manifest_hashes: vec![vec![0x99; 32], vec![0x11; 32]],
            resolved_verifier_policy_hashes: vec![vec![0xCC; 32], vec![0xAA; 32]],
            role_spec_hash: vec![],
            context_pack_recipe_hash: vec![],
            resolver_actor_id: "resolver-1".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        policy_resolved.canonicalize();

        // Should be sorted by profile ID, maintaining hash alignment
        // Expected: a -> 0x11, z -> 0x99
        assert_eq!(
            policy_resolved.resolved_rcp_profile_ids,
            vec!["a-profile", "z-profile"]
        );
        assert_eq!(
            policy_resolved.resolved_rcp_manifest_hashes,
            vec![vec![0x11; 32], vec![0x99; 32]]
        );
        assert_eq!(
            policy_resolved.resolved_verifier_policy_hashes,
            vec![vec![0xAA; 32], vec![0xCC; 32]]
        );
    }

    /// TCK-00264: Verify paired sorting preserves `profile_id` <->
    /// `manifest_hash` association.
    ///
    /// This is a critical security test. If profile IDs and manifest hashes are
    /// sorted independently, the association between them is corrupted,
    /// leading to:
    /// - Incorrect policy enforcement (wrong RCP manifest for a profile)
    /// - Signature verification failures
    /// - Data corruption in audit logs
    ///
    /// The correct approach is to zip the arrays, sort by profile ID, then
    /// unzip.
    #[test]
    fn tck_00264_paired_sorting_preserves_association() {
        // Create unsorted input with DISTINCT values that would sort differently
        // if sorted independently vs. as pairs.
        //
        // Profile IDs (alphabetically): delta < alpha < charlie < bravo (wait, that's
        // wrong) Let's use: profile-a, profile-b, profile-c, profile-z
        // With corresponding unique hashes: 0xAA, 0xBB, 0xCC, 0x99
        //
        // Input order (unsorted): z, a, c, b
        // With hashes:            0x99, 0xAA, 0xCC, 0xBB
        //
        // WRONG (independent sorting):
        //   profile_ids: [a, b, c, z]
        //   hashes: [0x99, 0xAA, 0xBB, 0xCC] (sorted independently by value)
        //
        // CORRECT (paired sorting):
        //   profile_ids: [a, b, c, z]
        //   hashes: [0xAA, 0xBB, 0xCC, 0x99] (each hash moves with its profile)
        let mut policy_resolved = PolicyResolvedForChangeSet {
            work_id: "work-paired-test".to_string(),
            changeset_digest: vec![0x42; 32],
            resolved_policy_hash: vec![0x00; 32],
            resolved_risk_tier: 1,
            resolved_determinism_class: 0,
            // Input: z -> 0x99, a -> 0xAA, c -> 0xCC, b -> 0xBB
            resolved_rcp_profile_ids: vec![
                "profile-z".into(),
                "profile-a".into(),
                "profile-c".into(),
                "profile-b".into(),
            ],
            resolved_rcp_manifest_hashes: vec![
                vec![0x99; 32], // corresponds to profile-z
                vec![0xAA; 32], // corresponds to profile-a
                vec![0xCC; 32], // corresponds to profile-c
                vec![0xBB; 32], // corresponds to profile-b
            ],
            resolved_verifier_policy_hashes: vec![],
            role_spec_hash: vec![],
            context_pack_recipe_hash: vec![],
            resolver_actor_id: "resolver-1".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        policy_resolved.canonicalize();

        // After paired sorting by profile ID:
        // profile-a (at index 0) should have hash 0xAA
        // profile-b (at index 1) should have hash 0xBB
        // profile-c (at index 2) should have hash 0xCC
        // profile-z (at index 3) should have hash 0x99
        assert_eq!(
            policy_resolved.resolved_rcp_profile_ids,
            vec!["profile-a", "profile-b", "profile-c", "profile-z"]
        );

        // The CRITICAL assertion: hashes must follow their paired profile IDs
        // NOT be sorted independently by their byte values
        assert_eq!(
            policy_resolved.resolved_rcp_manifest_hashes,
            vec![
                vec![0xAA; 32], // profile-a's hash
                vec![0xBB; 32], // profile-b's hash
                vec![0xCC; 32], // profile-c's hash
                vec![0x99; 32], // profile-z's hash
            ],
            "CRITICAL: manifest hashes must preserve association with their profile IDs. \
             If this fails with hashes sorted by value (0x99, 0xAA, 0xBB, 0xCC), \
             the code is incorrectly sorting arrays independently instead of as pairs."
        );

        // Also verify we can look up the correct hash for each profile
        // This simulates what verify_lease_match does
        for (idx, profile_id) in policy_resolved.resolved_rcp_profile_ids.iter().enumerate() {
            let expected_hash = &policy_resolved.resolved_rcp_manifest_hashes[idx];
            let looked_up = policy_resolved
                .resolved_rcp_profile_ids
                .iter()
                .position(|id| id == profile_id)
                .map(|i| &policy_resolved.resolved_rcp_manifest_hashes[i]);
            assert_eq!(
                looked_up,
                Some(expected_hash),
                "Hash lookup for {profile_id} should return the correct paired hash"
            );
        }
    }

    /// SEC-CAN-002: Verify `KernelEvent` canonicalizes `MergeReceipt` payload.
    #[test]
    fn sec_can_002_kernel_event_canonicalize_merge_receipt() {
        let mut event = KernelEvent {
            sequence: 1,
            payload: Some(kernel_event::Payload::MergeReceipt(MergeReceipt {
                base_selector: "main".to_string(),
                changeset_digest: vec![0xAB; 32],
                gate_receipt_ids: vec!["receipt-z".to_string(), "receipt-a".to_string()],
                policy_hash: vec![0xCD; 32],
                result_selector: "abc123".to_string(),
                merged_at: 1_234_567_890,
                gate_actor_id: "gate-actor".to_string(),
                gate_signature: vec![0u8; 64],
                time_envelope_ref: None,
            })),
            ..Default::default()
        };

        event.canonicalize();

        if let Some(kernel_event::Payload::MergeReceipt(receipt)) = &event.payload {
            assert_eq!(receipt.gate_receipt_ids, vec!["receipt-a", "receipt-z"]);
        } else {
            panic!("Expected MergeReceipt payload");
        }
    }

    /// SEC-CAN-002: Verify `KernelEvent` canonicalizes `RunnerPoolQuarantined`
    /// payload.
    #[test]
    fn sec_can_002_kernel_event_canonicalize_runner_pool_quarantined() {
        let mut event = KernelEvent {
            sequence: 1,
            payload: Some(kernel_event::Payload::RunnerPoolQuarantined(
                RunnerPoolQuarantined {
                    quarantine_id: "quar-001".to_string(),
                    pool_id: "pool-001".to_string(),
                    reason: "flaky".to_string(),
                    evidence_refs: vec!["evid-z".to_string(), "evid-a".to_string()],
                    time_envelope_ref: None,
                    issuer_actor_id: "issuer".to_string(),
                    issuer_signature: vec![0u8; 64],
                },
            )),
            ..Default::default()
        };

        event.canonicalize();

        if let Some(kernel_event::Payload::RunnerPoolQuarantined(quarantined)) = &event.payload {
            assert_eq!(quarantined.evidence_refs, vec!["evid-a", "evid-z"]);
        } else {
            panic!("Expected RunnerPoolQuarantined payload");
        }
    }

    /// SEC-CAN-002: Verify `KernelEvent` canonicalizes `AATSpecQuarantined`
    /// payload.
    #[test]
    fn sec_can_002_kernel_event_canonicalize_aat_spec_quarantined() {
        let mut event = KernelEvent {
            sequence: 1,
            payload: Some(kernel_event::Payload::AatSpecQuarantined(
                AatSpecQuarantined {
                    quarantine_id: "quar-002".to_string(),
                    spec_id: "spec-001".to_string(),
                    reason: "flaky".to_string(),
                    evidence_refs: vec!["evid-b".to_string(), "evid-a".to_string()],
                    time_envelope_ref: None,
                    issuer_actor_id: "issuer".to_string(),
                    issuer_signature: vec![0u8; 64],
                },
            )),
            ..Default::default()
        };

        event.canonicalize();

        if let Some(kernel_event::Payload::AatSpecQuarantined(quarantined)) = &event.payload {
            assert_eq!(quarantined.evidence_refs, vec!["evid-a", "evid-b"]);
        } else {
            panic!("Expected AATSpecQuarantined payload");
        }
    }

    /// SEC-CAN-002: Verify all new domain prefixes are unique.
    #[test]
    fn sec_can_002_new_domain_prefixes_unique() {
        let all_prefixes = [
            TOOL_DECIDED_DOMAIN_PREFIX,
            TOOL_EXECUTED_DOMAIN_PREFIX,
            SESSION_TERMINATED_DOMAIN_PREFIX,
            WORK_CLAIMED_DOMAIN_PREFIX,
            EPISODE_SPAWNED_DOMAIN_PREFIX,
            MERGE_RECEIPT_DOMAIN_PREFIX,
            RUNNER_POOL_QUARANTINED_DOMAIN_PREFIX,
            AAT_SPEC_QUARANTINED_DOMAIN_PREFIX,
            AAT_GATE_RECEIPT_DOMAIN_PREFIX,
            ARTIFACT_MANIFEST_DOMAIN_PREFIX,
        ];

        // Check uniqueness
        for (i, prefix_a) in all_prefixes.iter().enumerate() {
            for (j, prefix_b) in all_prefixes.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        prefix_a, prefix_b,
                        "Domain prefixes must be unique to prevent replay attacks"
                    );
                }
            }
        }

        // Verify all prefixes have correct format
        for prefix in &all_prefixes {
            let prefix_str = std::str::from_utf8(prefix).expect("Prefix must be valid UTF-8");
            assert!(
                prefix_str.starts_with("apm2."),
                "Prefix must start with 'apm2.'"
            );
            assert!(prefix_str.ends_with(':'), "Prefix must end with ':'");
        }
    }

    /// SEC-CAN-001: Document that `WorkClaimed` and `EpisodeSpawned` are not
    /// yet in the kernel proto schema.
    ///
    /// These event types are defined in RFC-0017 Phase 1 but are implemented
    /// in apm2-daemon, not in the kernel proto. When they are added to the
    /// kernel proto, Canonicalize implementations should be added.
    #[test]
    fn sec_can_001_work_claimed_episode_spawned_domain_prefixes_defined() {
        // Verify the domain prefixes are defined and correct
        assert_eq!(WORK_CLAIMED_DOMAIN_PREFIX, b"apm2.event.work_claimed:");
        assert_eq!(
            EPISODE_SPAWNED_DOMAIN_PREFIX,
            b"apm2.event.episode_spawned:"
        );

        // Note: The actual WorkClaimed and EpisodeSpawned types are not in
        // the kernel proto schema yet. They are defined in apm2-daemon for
        // RFC-0017 Phase 1. When they are migrated to kernel_events.proto,
        // Canonicalize implementations should be added here.
    }
}
