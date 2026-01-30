//! Evidence lifecycle reducer implementation.

use std::collections::HashMap;

use prost::Message;
use serde::{Deserialize, Serialize};

use super::category::EvidenceCategory;
use super::classification::DataClassification;
use super::error::EvidenceError;
use super::state::{Evidence, EvidenceBundle};
use crate::crypto::{HASH_SIZE, Hash};
use crate::events::{EvidenceEvent, evidence_event};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

const MAX_ID_LEN: usize = 256;
const MAX_COMMAND_IDS: usize = 100;

/// State maintained by the evidence reducer.
///
/// Tracks all published evidence and provides efficient lookup by evidence ID,
/// work ID, and category.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceReducerState {
    /// Map of evidence ID to evidence.
    pub evidence: HashMap<String, Evidence>,

    /// Map of work ID to list of evidence IDs.
    pub evidence_by_work: HashMap<String, Vec<String>>,

    /// Map of work ID to evidence bundle (if assembled).
    pub bundles: HashMap<String, EvidenceBundle>,
}

impl EvidenceReducerState {
    /// Creates a new empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of evidence items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.evidence.len()
    }

    /// Returns `true` if there is no evidence.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.evidence.is_empty()
    }

    /// Returns the evidence for a given ID, if it exists.
    #[must_use]
    pub fn get(&self, evidence_id: &str) -> Option<&Evidence> {
        self.evidence.get(evidence_id)
    }

    /// Returns all evidence for a given work ID.
    #[must_use]
    pub fn get_by_work(&self, work_id: &str) -> Vec<&Evidence> {
        self.evidence_by_work
            .get(work_id)
            .map(|ids| ids.iter().filter_map(|id| self.evidence.get(id)).collect())
            .unwrap_or_default()
    }

    /// Returns all evidence with the given category.
    #[must_use]
    pub fn get_by_category(&self, category: EvidenceCategory) -> Vec<&Evidence> {
        self.evidence
            .values()
            .filter(|e| e.category == category)
            .collect()
    }

    /// Returns all evidence for a work ID with the given category.
    #[must_use]
    pub fn get_by_work_and_category(
        &self,
        work_id: &str,
        category: EvidenceCategory,
    ) -> Vec<&Evidence> {
        self.get_by_work(work_id)
            .into_iter()
            .filter(|e| e.category == category)
            .collect()
    }

    /// Returns the number of evidence items for a work ID.
    #[must_use]
    pub fn count_by_work(&self, work_id: &str) -> usize {
        self.evidence_by_work.get(work_id).map_or(0, Vec::len)
    }

    /// Returns the bundle for a work ID, if one exists.
    #[must_use]
    pub fn get_bundle(&self, work_id: &str) -> Option<&EvidenceBundle> {
        self.bundles.get(work_id)
    }

    /// Returns the total size of all evidence for a work ID.
    ///
    /// Uses saturating addition to prevent overflow. Returns `usize::MAX` if
    /// the total would overflow.
    #[must_use]
    pub fn total_size_by_work(&self, work_id: &str) -> usize {
        self.get_by_work(work_id)
            .iter()
            .fold(0usize, |acc, e| acc.saturating_add(e.artifact_size))
    }

    /// Returns all distinct categories for a work ID.
    #[must_use]
    pub fn categories_by_work(&self, work_id: &str) -> Vec<EvidenceCategory> {
        let mut categories: Vec<_> = self
            .get_by_work(work_id)
            .iter()
            .map(|e| e.category)
            .collect();
        categories.sort_by_key(|c| *c as u8);
        categories.dedup();
        categories
    }
}

/// Reducer for evidence lifecycle events.
///
/// Processes evidence events and maintains the state of all published evidence.
/// Supports indexing by work ID and category for efficient lookups.
///
/// # Trust Boundary: Content Verification
///
/// This reducer does NOT verify that artifact content matches the hash. Content
/// verification is the responsibility of the CAS layer. The reducer assumes:
///
/// 1. **CAS integrity**: The CAS has verified content on storage.
/// 2. **Hash authenticity**: The event was validated by the command handler
///    before being appended to the ledger.
#[derive(Debug, Default)]
pub struct EvidenceReducer {
    state: EvidenceReducerState,
}

impl EvidenceReducer {
    /// Creates a new evidence reducer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles an evidence published event.
    fn handle_published(
        &mut self,
        event: &crate::events::EvidencePublished,
        actor_id: &str,
        timestamp: u64,
    ) -> Result<(), EvidenceError> {
        let evidence_id = &event.evidence_id;
        let work_id = &event.work_id;

        // Validate ID lengths
        if evidence_id.is_empty() {
            return Err(EvidenceError::InvalidEvidenceId {
                value: evidence_id.clone(),
            });
        }
        if evidence_id.len() > MAX_ID_LEN {
            return Err(EvidenceError::InvalidEvidenceId {
                value: format!("exceeds {MAX_ID_LEN} bytes"),
            });
        }
        if work_id.is_empty() {
            return Err(EvidenceError::InvalidWorkId {
                value: work_id.clone(),
            });
        }
        if work_id.len() > MAX_ID_LEN {
            return Err(EvidenceError::InvalidWorkId {
                value: format!("exceeds {MAX_ID_LEN} bytes"),
            });
        }

        // Check for duplicate evidence ID
        if self.state.evidence.contains_key(evidence_id) {
            return Err(EvidenceError::DuplicateEvidence {
                evidence_id: evidence_id.clone(),
            });
        }

        // Validate and parse category
        let category = EvidenceCategory::parse(&event.category)?;

        // Validate artifact hash
        if event.artifact_hash.len() != HASH_SIZE {
            return Err(EvidenceError::HashMismatch {
                expected: format!("{HASH_SIZE} bytes"),
                actual: format!("{} bytes", event.artifact_hash.len()),
            });
        }

        // Convert hash to fixed-size array
        let mut artifact_hash: Hash = [0u8; HASH_SIZE];
        artifact_hash.copy_from_slice(&event.artifact_hash);

        // Validate verification command count (DoS protection)
        if event.verification_command_ids.len() > MAX_COMMAND_IDS {
            return Err(EvidenceError::InvalidVerificationCommand {
                index: MAX_COMMAND_IDS,
                reason: format!("exceeds maximum of {MAX_COMMAND_IDS} commands"),
            });
        }

        // Parse classification from event (default to Internal if empty for backward
        // compat)
        let classification = if event.classification.is_empty() {
            DataClassification::Internal
        } else {
            DataClassification::parse(&event.classification)?
        };

        // Parse metadata from "key=value" strings
        let metadata: Vec<(String, String)> = event
            .metadata
            .iter()
            .filter_map(|s| {
                let parts: Vec<&str> = s.splitn(2, '=').collect();
                if parts.len() == 2 {
                    Some((parts[0].to_string(), parts[1].to_string()))
                } else {
                    None
                }
            })
            .collect();

        // Create evidence with data from the event
        let evidence = Evidence::new(
            evidence_id.clone(),
            work_id.clone(),
            category,
            artifact_hash,
            usize::try_from(event.artifact_size).unwrap_or(usize::MAX),
            classification,
            event.verification_command_ids.clone(),
            metadata,
            timestamp,
            actor_id.to_string(),
        );

        // Insert evidence
        self.state.evidence.insert(evidence_id.clone(), evidence);

        // Update work index
        self.state
            .evidence_by_work
            .entry(work_id.clone())
            .or_default()
            .push(evidence_id.clone());

        Ok(())
    }

    /// Handles a gate receipt generated event.
    ///
    /// When a gate receipt is generated, we assemble the evidence bundle
    /// for the work item.
    fn handle_gate_receipt(&mut self, event: &crate::events::GateReceiptGenerated, timestamp: u64) {
        let work_id = &event.work_id;

        // Get all evidence for this work
        let evidence_ids: Vec<String> = self
            .state
            .evidence_by_work
            .get(work_id)
            .cloned()
            .unwrap_or_default();

        // Collect categories
        let categories = self.state.categories_by_work(work_id);

        // Calculate total size
        let total_size = self.state.total_size_by_work(work_id);

        // Compute bundle hash from evidence IDs (sorted for determinism)
        let mut sorted_ids = evidence_ids.clone();
        sorted_ids.sort();
        let bundle_content = sorted_ids.join(",");
        let bundle_hash = crate::crypto::EventHasher::hash_content(bundle_content.as_bytes());

        // Create bundle
        let bundle = EvidenceBundle::new(
            work_id.clone(),
            bundle_hash,
            evidence_ids,
            categories,
            total_size,
            timestamp,
        );

        self.state.bundles.insert(work_id.clone(), bundle);
    }
}

impl Reducer for EvidenceReducer {
    type State = EvidenceReducerState;
    type Error = EvidenceError;

    fn name(&self) -> &'static str {
        "evidence-publisher"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        // Only handle evidence events
        if !event.event_type.starts_with("evidence.") {
            return Ok(());
        }

        let evidence_event = EvidenceEvent::decode(&event.payload[..]).map_err(|e| {
            EvidenceError::InvalidEvidenceId {
                value: format!("decode error: {e}"),
            }
        })?;

        let timestamp = event.timestamp_ns;

        match &evidence_event.event {
            Some(evidence_event::Event::Published(e)) => {
                self.handle_published(e, &event.actor_id, timestamp)
            },
            Some(evidence_event::Event::GateReceipt(e)) => {
                self.handle_gate_receipt(e, timestamp);
                Ok(())
            },
            // GateRunCompleted events are handled by the FAC admission logic,
            // not the evidence reducer
            Some(evidence_event::Event::GateRunCompleted(_)) | None => Ok(()),
        }
    }

    fn state(&self) -> &Self::State {
        &self.state
    }

    fn state_mut(&mut self) -> &mut Self::State {
        &mut self.state
    }

    fn reset(&mut self) {
        self.state = EvidenceReducerState::default();
    }
}

/// Helper functions for creating evidence event payloads.
#[cfg(test)]
pub mod helpers {
    use prost::Message;

    use crate::events::{EvidenceEvent, EvidencePublished, GateReceiptGenerated, evidence_event};

    /// Creates an `EvidencePublished` event payload.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn evidence_published_payload(
        evidence_id: &str,
        work_id: &str,
        category: &str,
        artifact_hash: Vec<u8>,
        verification_command_ids: Vec<String>,
        classification: &str,
        artifact_size: u64,
        metadata: Vec<String>,
    ) -> Vec<u8> {
        let published = EvidencePublished {
            evidence_id: evidence_id.to_string(),
            work_id: work_id.to_string(),
            category: category.to_string(),
            artifact_hash,
            verification_command_ids,
            classification: classification.to_string(),
            artifact_size,
            metadata,
        };
        let event = EvidenceEvent {
            event: Some(evidence_event::Event::Published(published)),
        };
        event.encode_to_vec()
    }

    /// Creates a `GateReceiptGenerated` event payload.
    #[must_use]
    pub fn gate_receipt_payload(
        receipt_id: &str,
        gate_id: &str,
        work_id: &str,
        result: &str,
        evidence_ids: Vec<String>,
        receipt_signature: Vec<u8>,
    ) -> Vec<u8> {
        let receipt = GateReceiptGenerated {
            receipt_id: receipt_id.to_string(),
            gate_id: gate_id.to_string(),
            work_id: work_id.to_string(),
            result: result.to_string(),
            evidence_ids,
            receipt_signature,
        };
        let event = EvidenceEvent {
            event: Some(evidence_event::Event::GateReceipt(receipt)),
        };
        event.encode_to_vec()
    }
}
