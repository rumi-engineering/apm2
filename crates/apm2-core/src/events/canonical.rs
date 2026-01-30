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

use super::{
    AdjudicationRequested, EvidencePublished, GateReceiptGenerated, KernelEvent, LeaseConflict,
    PolicyResolvedForChangeSet, WorkCompleted, WorkOpened, adjudication_event, evidence_event,
    kernel_event, lease_event, work_event,
};

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
}
