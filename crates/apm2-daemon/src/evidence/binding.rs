//! Evidence binding for tool receipts.
//!
//! This module implements evidence binding per AD-RECEIPT-001. Evidence
//! binding collects CAS hashes for tool arguments, results, and other
//! artifacts and computes a binding hash.
//!
//! # Architecture
//!
//! ```text
//! EvidenceBinding
//!     |-- envelope_hash: Hash (bound to episode envelope)
//!     |-- policy_hash: Hash (policy version used)
//!     |-- args_hash: Option<Hash> (CAS hash of tool arguments)
//!     |-- result_hash: Option<Hash> (CAS hash of tool result)
//!     |-- additional_refs: Vec<Hash> (other evidence hashes)
//!     `-- compute_binding_hash() -> Hash
//! ```
//!
//! # Security Model
//!
//! - All hashes use BLAKE3-256
//! - Binding hash commits to all evidence
//! - Evidence refs are sorted for determinism
//!
//! # Contract References
//!
//! - AD-RECEIPT-001: Tool receipt generation
//! - AD-VERIFY-001: Deterministic serialization
//! - CTR-2616: Hash chains commit to all related events

use prost::Message;

use super::receipt::{Hash, MAX_EVIDENCE_REFS, ReceiptError};

// =============================================================================
// EvidenceBinding
// =============================================================================

/// Evidence binding for collecting and hashing evidence artifacts.
///
/// This collects CAS hashes for tool arguments, results, and other
/// evidence artifacts, then computes a binding hash that commits to
/// all evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBinding {
    /// Hash of the episode envelope.
    envelope_hash: Hash,

    /// Hash of the policy version used.
    policy_hash: Hash,

    /// Hash of the tool arguments (optional).
    args_hash: Option<Hash>,

    /// Hash of the tool result (optional).
    result_hash: Option<Hash>,

    /// Additional evidence references.
    additional_refs: Vec<Hash>,
}

impl EvidenceBinding {
    /// Creates a new evidence binding with envelope and policy hashes.
    ///
    /// # Arguments
    ///
    /// * `envelope_hash` - BLAKE3 hash of the episode envelope
    /// * `policy_hash` - BLAKE3 hash of the policy version
    #[must_use]
    pub const fn new(envelope_hash: Hash, policy_hash: Hash) -> Self {
        Self {
            envelope_hash,
            policy_hash,
            args_hash: None,
            result_hash: None,
            additional_refs: Vec::new(),
        }
    }

    /// Returns the envelope hash.
    #[must_use]
    pub const fn envelope_hash(&self) -> &Hash {
        &self.envelope_hash
    }

    /// Returns the policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    /// Sets the tool arguments hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - BLAKE3 hash of the tool arguments
    pub const fn set_args_hash(&mut self, hash: Hash) {
        self.args_hash = Some(hash);
    }

    /// Returns the tool arguments hash if set.
    #[must_use]
    pub const fn args_hash(&self) -> Option<&Hash> {
        self.args_hash.as_ref()
    }

    /// Sets the tool arguments hash (builder pattern).
    #[must_use]
    pub const fn with_args_hash(mut self, hash: Hash) -> Self {
        self.args_hash = Some(hash);
        self
    }

    /// Sets the tool result hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - BLAKE3 hash of the tool result
    pub const fn set_result_hash(&mut self, hash: Hash) {
        self.result_hash = Some(hash);
    }

    /// Returns the tool result hash if set.
    #[must_use]
    pub const fn result_hash(&self) -> Option<&Hash> {
        self.result_hash.as_ref()
    }

    /// Sets the tool result hash (builder pattern).
    #[must_use]
    pub const fn with_result_hash(mut self, hash: Hash) -> Self {
        self.result_hash = Some(hash);
        self
    }

    /// Adds an additional evidence reference.
    ///
    /// # Arguments
    ///
    /// * `hash` - BLAKE3 hash of the evidence artifact
    ///
    /// # Errors
    ///
    /// Returns an error if adding the reference would exceed
    /// `MAX_EVIDENCE_REFS`.
    pub fn add_evidence_ref(&mut self, hash: Hash) -> Result<(), ReceiptError> {
        // Count total refs (args + result + additional) without allocation
        // Using O(1) computation instead of calling evidence_refs() which is O(n)
        let args_count = usize::from(self.args_hash.is_some());
        let result_count = usize::from(self.result_hash.is_some());
        let total = args_count + result_count + self.additional_refs.len() + 1;
        if total > MAX_EVIDENCE_REFS {
            return Err(ReceiptError::TooManyEvidenceRefs {
                count: total,
                max: MAX_EVIDENCE_REFS,
            });
        }
        self.additional_refs.push(hash);
        Ok(())
    }

    /// Returns all evidence references (args, result, and additional).
    ///
    /// The references are returned in a consistent order:
    /// 1. `args_hash` (if present)
    /// 2. `result_hash` (if present)
    /// 3. `additional_refs` (in insertion order)
    #[must_use]
    pub fn evidence_refs(&self) -> Vec<Hash> {
        let mut refs = Vec::new();
        if let Some(hash) = self.args_hash {
            refs.push(hash);
        }
        if let Some(hash) = self.result_hash {
            refs.push(hash);
        }
        refs.extend(&self.additional_refs);
        refs
    }

    /// Computes the binding hash from all evidence.
    ///
    /// The binding hash commits to:
    /// - `envelope_hash`
    /// - `policy_hash`
    /// - All evidence refs (sorted for determinism)
    ///
    /// Per AD-VERIFY-001, evidence refs are sorted before hashing
    /// to ensure deterministic output regardless of insertion order.
    #[must_use]
    pub fn compute_binding_hash(&self) -> Hash {
        let bytes = self.canonical_bytes();
        *blake3::hash(&bytes).as_bytes()
    }

    /// Returns the canonical bytes for the binding.
    ///
    /// Per AD-VERIFY-001:
    /// - Fields are in tag order
    /// - Evidence refs are sorted by hash value
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Collect and sort all evidence refs
        let mut sorted_refs = self.evidence_refs();
        sorted_refs.sort_unstable();

        let proto = EvidenceBindingProto {
            envelope_hash: self.envelope_hash.to_vec(),
            policy_hash: self.policy_hash.to_vec(),
            evidence_refs: sorted_refs.into_iter().map(|h| h.to_vec()).collect(),
        };
        proto.encode_to_vec()
    }

    /// Returns the number of evidence references.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence_refs().len()
    }

    /// Returns `true` if there are no evidence references beyond
    /// envelope/policy.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.args_hash.is_none() && self.result_hash.is_none() && self.additional_refs.is_empty()
    }
}

/// Internal protobuf representation for evidence binding.
#[derive(Clone, PartialEq, Message)]
struct EvidenceBindingProto {
    #[prost(bytes = "vec", tag = "1")]
    envelope_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    policy_hash: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    evidence_refs: Vec<Vec<u8>>,
}

// =============================================================================
// ToolEvidenceCollector
// =============================================================================

/// Collector for tool execution evidence.
///
/// This provides a convenient way to collect evidence for a single tool
/// execution and create the corresponding binding.
#[derive(Debug, Clone)]
pub struct ToolEvidenceCollector {
    /// The underlying binding.
    binding: EvidenceBinding,

    /// Request ID for this tool execution.
    request_id: String,

    /// Capability ID that authorized the execution.
    capability_id: String,
}

impl ToolEvidenceCollector {
    /// Creates a new collector for a tool execution.
    ///
    /// # Arguments
    ///
    /// * `envelope_hash` - Hash of the episode envelope
    /// * `policy_hash` - Hash of the policy version
    /// * `request_id` - Unique request ID
    /// * `capability_id` - Capability that authorized execution
    #[must_use]
    pub fn new(
        envelope_hash: Hash,
        policy_hash: Hash,
        request_id: impl Into<String>,
        capability_id: impl Into<String>,
    ) -> Self {
        Self {
            binding: EvidenceBinding::new(envelope_hash, policy_hash),
            request_id: request_id.into(),
            capability_id: capability_id.into(),
        }
    }

    /// Records the tool arguments.
    ///
    /// # Arguments
    ///
    /// * `args` - Serialized tool arguments
    ///
    /// # Returns
    ///
    /// The BLAKE3 hash of the arguments.
    pub fn record_args(&mut self, args: &[u8]) -> Hash {
        let hash = *blake3::hash(args).as_bytes();
        self.binding.set_args_hash(hash);
        hash
    }

    /// Records the tool result.
    ///
    /// # Arguments
    ///
    /// * `result` - Serialized tool result
    ///
    /// # Returns
    ///
    /// The BLAKE3 hash of the result.
    pub fn record_result(&mut self, result: &[u8]) -> Hash {
        let hash = *blake3::hash(result).as_bytes();
        self.binding.set_result_hash(hash);
        hash
    }

    /// Adds additional evidence.
    ///
    /// # Arguments
    ///
    /// * `evidence` - Additional evidence bytes
    ///
    /// # Returns
    ///
    /// The BLAKE3 hash of the evidence.
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed `MAX_EVIDENCE_REFS`.
    pub fn add_evidence(&mut self, evidence: &[u8]) -> Result<Hash, ReceiptError> {
        let hash = *blake3::hash(evidence).as_bytes();
        self.binding.add_evidence_ref(hash)?;
        Ok(hash)
    }

    /// Adds a pre-computed hash as evidence.
    ///
    /// # Arguments
    ///
    /// * `hash` - Pre-computed BLAKE3 hash
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed `MAX_EVIDENCE_REFS`.
    pub fn add_evidence_hash(&mut self, hash: Hash) -> Result<(), ReceiptError> {
        self.binding.add_evidence_ref(hash)
    }

    /// Returns the request ID.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the capability ID.
    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    /// Returns a reference to the underlying binding.
    #[must_use]
    pub const fn binding(&self) -> &EvidenceBinding {
        &self.binding
    }

    /// Consumes the collector and returns the binding.
    #[must_use]
    pub fn into_binding(self) -> EvidenceBinding {
        self.binding
    }

    /// Computes the binding hash.
    #[must_use]
    pub fn compute_binding_hash(&self) -> Hash {
        self.binding.compute_binding_hash()
    }

    /// Returns all evidence references.
    #[must_use]
    pub fn evidence_refs(&self) -> Vec<Hash> {
        self.binding.evidence_refs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_envelope_hash() -> Hash {
        [0xaa; 32]
    }

    fn test_policy_hash() -> Hash {
        [0xbb; 32]
    }

    #[test]
    fn test_evidence_binding_new() {
        let binding = EvidenceBinding::new(test_envelope_hash(), test_policy_hash());
        assert_eq!(*binding.envelope_hash(), test_envelope_hash());
        assert_eq!(*binding.policy_hash(), test_policy_hash());
        assert!(binding.is_empty());
    }

    #[test]
    fn test_evidence_binding_with_args() {
        let binding = EvidenceBinding::new(test_envelope_hash(), test_policy_hash())
            .with_args_hash([0x11; 32]);

        assert_eq!(*binding.args_hash().unwrap(), [0x11; 32]);
        assert!(!binding.is_empty());
    }

    #[test]
    fn test_evidence_binding_with_result() {
        let binding = EvidenceBinding::new(test_envelope_hash(), test_policy_hash())
            .with_result_hash([0x22; 32]);

        assert_eq!(*binding.result_hash().unwrap(), [0x22; 32]);
        assert!(!binding.is_empty());
    }

    #[test]
    fn test_evidence_binding_add_ref() {
        let mut binding = EvidenceBinding::new(test_envelope_hash(), test_policy_hash());
        binding.add_evidence_ref([0x33; 32]).unwrap();
        binding.add_evidence_ref([0x44; 32]).unwrap();

        assert_eq!(binding.evidence_count(), 2);
    }

    #[test]
    fn test_evidence_refs_order() {
        let binding = EvidenceBinding::new(test_envelope_hash(), test_policy_hash())
            .with_args_hash([0x11; 32])
            .with_result_hash([0x22; 32]);

        let refs = binding.evidence_refs();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], [0x11; 32]); // args first
        assert_eq!(refs[1], [0x22; 32]); // result second
    }

    #[test]
    fn test_evidence_binding_too_many_refs() {
        let mut binding = EvidenceBinding::new(test_envelope_hash(), test_policy_hash());

        // Fill up to limit
        #[allow(clippy::cast_possible_truncation)]
        for i in 0..MAX_EVIDENCE_REFS {
            binding.add_evidence_ref([(i % 256) as u8; 32]).unwrap();
        }

        // One more should fail
        let result = binding.add_evidence_ref([0xff; 32]);
        assert!(matches!(
            result,
            Err(ReceiptError::TooManyEvidenceRefs { .. })
        ));
    }

    #[test]
    fn test_binding_hash_determinism() {
        let binding1 = EvidenceBinding::new(test_envelope_hash(), test_policy_hash())
            .with_args_hash([0x11; 32])
            .with_result_hash([0x22; 32]);

        let binding2 = EvidenceBinding::new(test_envelope_hash(), test_policy_hash())
            .with_args_hash([0x11; 32])
            .with_result_hash([0x22; 32]);

        assert_eq!(
            binding1.compute_binding_hash(),
            binding2.compute_binding_hash()
        );
    }

    #[test]
    fn test_binding_hash_changes_with_evidence() {
        let binding_empty = EvidenceBinding::new(test_envelope_hash(), test_policy_hash());

        let binding_with_args = EvidenceBinding::new(test_envelope_hash(), test_policy_hash())
            .with_args_hash([0x11; 32]);

        assert_ne!(
            binding_empty.compute_binding_hash(),
            binding_with_args.compute_binding_hash()
        );
    }

    #[test]
    fn test_canonical_bytes_sorts_evidence_refs() {
        let mut binding1 = EvidenceBinding::new(test_envelope_hash(), test_policy_hash());
        binding1.add_evidence_ref([0xff; 32]).unwrap();
        binding1.add_evidence_ref([0x00; 32]).unwrap();
        binding1.add_evidence_ref([0x88; 32]).unwrap();

        let mut binding2 = EvidenceBinding::new(test_envelope_hash(), test_policy_hash());
        binding2.add_evidence_ref([0x00; 32]).unwrap();
        binding2.add_evidence_ref([0x88; 32]).unwrap();
        binding2.add_evidence_ref([0xff; 32]).unwrap();

        // Despite different insertion order, canonical bytes should be the same
        assert_eq!(binding1.canonical_bytes(), binding2.canonical_bytes());
        assert_eq!(
            binding1.compute_binding_hash(),
            binding2.compute_binding_hash()
        );
    }

    #[test]
    fn test_tool_evidence_collector() {
        let mut collector = ToolEvidenceCollector::new(
            test_envelope_hash(),
            test_policy_hash(),
            "req-001",
            "cap-read",
        );

        assert_eq!(collector.request_id(), "req-001");
        assert_eq!(collector.capability_id(), "cap-read");

        let args_hash = collector.record_args(b"test args");
        let result_hash = collector.record_result(b"test result");

        // Hashes should be BLAKE3 of the content
        assert_eq!(args_hash, *blake3::hash(b"test args").as_bytes());
        assert_eq!(result_hash, *blake3::hash(b"test result").as_bytes());

        // Should have 2 evidence refs
        assert_eq!(collector.evidence_refs().len(), 2);
    }

    #[test]
    fn test_tool_evidence_collector_add_evidence() {
        let mut collector = ToolEvidenceCollector::new(
            test_envelope_hash(),
            test_policy_hash(),
            "req-001",
            "cap-read",
        );

        let hash = collector.add_evidence(b"extra evidence").unwrap();
        assert_eq!(hash, *blake3::hash(b"extra evidence").as_bytes());

        collector.add_evidence_hash([0xab; 32]).unwrap();

        assert_eq!(collector.evidence_refs().len(), 2);
    }

    #[test]
    fn test_tool_evidence_collector_into_binding() {
        let mut collector = ToolEvidenceCollector::new(
            test_envelope_hash(),
            test_policy_hash(),
            "req-001",
            "cap-read",
        );

        collector.record_args(b"args");
        collector.record_result(b"result");

        let binding = collector.into_binding();
        assert_eq!(binding.evidence_count(), 2);
    }

    #[test]
    fn test_evidence_binding_setters() {
        let mut binding = EvidenceBinding::new(test_envelope_hash(), test_policy_hash());

        binding.set_args_hash([0x11; 32]);
        assert_eq!(*binding.args_hash().unwrap(), [0x11; 32]);

        binding.set_result_hash([0x22; 32]);
        assert_eq!(*binding.result_hash().unwrap(), [0x22; 32]);
    }
}
