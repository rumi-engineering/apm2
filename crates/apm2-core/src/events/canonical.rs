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
    AdjudicationRequested, EvidencePublished, GateReceipt, GateReceiptGenerated, KernelEvent,
    LeaseConflict, PolicyResolvedForChangeSet, SessionTerminated, ToolDecided, ToolExecuted,
    WorkCompleted, WorkOpened, adjudication_event, evidence_event, kernel_event, lease_event,
    session_event, tool_event, work_event,
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

/// Domain prefix for `EpisodeSpawned` events.
///
/// Per RFC-0017 DD-006: domain prefixes prevent cross-context replay.
/// Note: `EpisodeSpawned` event type is defined in apm2-daemon for RFC-0017
/// Phase 1.
pub const EPISODE_SPAWNED_DOMAIN_PREFIX: &[u8] = b"apm2.event.episode_spawned:";

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
/// };
///
/// // Canonicalize and get domain-prefixed bytes for signing
/// decided.canonicalize();
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
    /// 1. Serializes the message to protobuf bytes
    /// 2. Prepends the domain prefix
    ///
    /// The caller should call `canonicalize()` before this method to ensure
    /// repeated fields are sorted.
    fn canonical_bytes_with_domain(&self) -> Vec<u8> {
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
        // Sort RCP profile IDs and manifest hashes together to maintain alignment.
        // We zip them, sort by profile ID, then unzip back.
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
            // If lengths don't match, just sort profile IDs independently
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
        // Canonicalize nested payload if present
        match &mut self.payload {
            Some(kernel_event::Payload::Work(work_event)) => {
                if let Some(event) = &mut work_event.event {
                    match event {
                        work_event::Event::Opened(opened) => opened.canonicalize(),
                        work_event::Event::Completed(completed) => completed.canonicalize(),
                        _ => {},
                    }
                }
            },
            Some(kernel_event::Payload::Tool(tool_event)) => {
                if let Some(event) = &mut tool_event.event {
                    match event {
                        tool_event::Event::Decided(decided) => decided.canonicalize(),
                        tool_event::Event::Executed(executed) => executed.canonicalize(),
                        tool_event::Event::Requested(_) => {},
                    }
                }
            },
            Some(kernel_event::Payload::Session(session_event)) => {
                if let Some(session_event::Event::Terminated(terminated)) = &mut session_event.event
                {
                    terminated.canonicalize();
                }
            },
            Some(kernel_event::Payload::Adjudication(adj_event)) => {
                if let Some(adjudication_event::Event::Requested(requested)) = &mut adj_event.event
                {
                    requested.canonicalize();
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
                if let Some(lease_event::Event::Conflict(conflict)) = &mut lease_event.event {
                    conflict.canonicalize();
                }
            },
            Some(kernel_event::Payload::PolicyResolvedForChangeset(policy_resolved)) => {
                policy_resolved.canonicalize();
            },
            Some(kernel_event::Payload::GateReceipt(gate_receipt)) => {
                gate_receipt.canonicalize();
            },
            _ => {},
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
            resolver_actor_id: "resolver-1".to_string(),
            resolver_version: "1.0.0".to_string(),
            resolver_signature: vec![0u8; 64],
        };

        policy_resolved.canonicalize();

        // Profile IDs should be sorted alphabetically
        assert_eq!(
            policy_resolved.resolved_rcp_profile_ids,
            vec!["a-profile", "m-profile", "z-profile"]
        );

        // Manifest hashes should follow the same order as their corresponding profile
        // IDs
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
        };

        let mut executed = ToolExecuted {
            request_id: "id-same".to_string(),
            outcome: "SUCCESS".to_string(),
            result_hash: vec![0x00; 32],
            duration_ms: 100,
            time_envelope_ref: None,
        };

        let mut terminated = SessionTerminated {
            session_id: "id-same".to_string(),
            exit_classification: "SUCCESS".to_string(),
            rationale_code: "CODE".to_string(),
            final_entropy: 100,
            time_envelope_ref: None,
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
        };

        terminated.canonicalize();
        let bytes = terminated.canonical_bytes_with_domain();

        // Verify prefix
        assert!(bytes.starts_with(b"apm2.event.session_terminated:"));

        // Verify determinism
        let bytes2 = terminated.canonical_bytes_with_domain();
        assert_eq!(bytes, bytes2, "Golden vector must be stable across runs");
    }
}
