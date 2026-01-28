//! Golden test vectors for receipt hash stability verification.
//!
//! This module contains golden vectors that verify the deterministic encoding
//! of tool receipt types. Each vector consists of:
//!
//! 1. A message constructed with specific field values
//! 2. The expected canonical bytes (hex-encoded)
//! 3. The expected BLAKE3 hash of the canonical bytes
//!
//! # Purpose
//!
//! Golden vectors serve multiple purposes:
//!
//! - **Determinism verification**: Ensure encoding produces identical bytes
//!   across versions, platforms, and library updates
//! - **Digest stability**: Verify that receipt digests remain stable across
//!   serialization cycles
//! - **Cross-platform consistency**: Ensure wire format is consistent
//!   regardless of compilation target
//!
//! # Contract References
//!
//! - AD-RECEIPT-001: Tool receipt generation
//! - AD-VERIFY-001: Deterministic Protobuf serialization (`canonical_bytes`)
//! - REQ-RECEIPT-001: Receipt requirements
//!
//! # Updating Vectors
//!
//! When message definitions change:
//! 1. Update the message construction in the vector
//! 2. Run tests to get new expected values
//! 3. Verify changes are intentional (breaking change = new protocol version)
//! 4. Update expected bytes and hashes

use super::receipt::{CanonicalizerId, ReceiptKind, ToolExecutionDetails, ToolReceipt};
use crate::episode::EpisodeId;

/// A golden test vector for receipt types.
pub struct GoldenVector {
    /// Human-readable name for the vector.
    pub name: &'static str,
    /// Contract reference (e.g., "AD-RECEIPT-001").
    pub contract: &'static str,
    /// Expected BLAKE3 hash of the canonical bytes (hex-encoded).
    pub expected_hash: &'static str,
    /// Expected canonical bytes (hex-encoded).
    pub expected_bytes: &'static str,
}

// ============================================================================
// ToolExecutionDetails vectors
// ============================================================================

/// Golden vector for tool execution details.
pub const TOOL_EXECUTION_DETAILS_VECTOR: GoldenVector = GoldenVector {
    name: "tool_execution_details",
    contract: "AD-RECEIPT-001",
    expected_hash: "7cf1174f923cc1267769138fcf222250351d9cee4c3aa3f3be00f3f6a4d125b5",
    expected_bytes: "0a077265712d3030311207636170253031311a20111111111111111111111111111111111111111111111111111111111111111122202222222222222222222222222222222222222222222222222222222222222222280132047465737438c0843d",
};

/// Golden vector for tool execution details without result message.
pub const TOOL_EXECUTION_DETAILS_NO_MESSAGE_VECTOR: GoldenVector = GoldenVector {
    name: "tool_execution_details_no_message",
    contract: "AD-RECEIPT-001",
    expected_hash: "7888fbdea6ff4d3f6fac195127d1fb2368a217a0f3d0a6cb2fafaf42a595f269",
    expected_bytes: "0a077265712d3030311207636170253031311a20111111111111111111111111111111111111111111111111111111111111111122202222222222222222222222222222222222222222222222222222222222222222280038c0843d",
};

// ============================================================================
// ToolReceipt vectors
// ============================================================================

/// Golden vector for a minimal tool execution receipt.
pub const RECEIPT_TOOL_EXECUTION_VECTOR: GoldenVector = GoldenVector {
    name: "receipt_tool_execution",
    contract: "AD-RECEIPT-001",
    expected_hash: "4d8dc1abbf7fb8f8017a58a84f856f3387d022a0b19751b37d317d34270a0a91",
    expected_bytes: "08011207657030303030311a20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2a0d61706d322d70726f746f2d76313001408080948bf08284d317525c0a077265712d3030311207636170253031311a20111111111111111111111111111111111111111111111111111111111111111122202222222222222222222222222222222222222222222222222222222222222222280138c0843d",
};

/// Golden vector for an episode start receipt.
pub const RECEIPT_EPISODE_START_VECTOR: GoldenVector = GoldenVector {
    name: "receipt_episode_start",
    contract: "AD-RECEIPT-001",
    expected_hash: "cf4fe8e40fa04fb0e83c25c161740b0f687643a9476bf0639055121e2f2c88ec",
    expected_bytes: "08021207657030303030321a20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2a0d61706d322d70726f746f2d76313001409582a6efc79e849111",
};

/// Golden vector for receipt with sorted evidence refs.
///
/// This tests that evidence refs are sorted in canonical bytes regardless
/// of insertion order.
pub const RECEIPT_SORTED_EVIDENCE_REFS_VECTOR: GoldenVector = GoldenVector {
    name: "receipt_sorted_evidence_refs",
    contract: "AD-VERIFY-001",
    expected_hash: "4f49c37ff1d1a268548c1a207d2345b722478d7dd52927b92112c338449e398c",
    expected_bytes: "08021207657030303030331a20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2a0d61706d322d70726f746f2d763130013a2000000000000000000000000000000000000000000000000000000000000000003a2088888888888888888888888888888888888888888888888888888888888888883a20ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4080e497d012",
};

// ============================================================================
// Helper functions
// ============================================================================

/// Constructs tool execution details for golden vector.
#[must_use]
pub fn construct_tool_execution_details() -> ToolExecutionDetails {
    ToolExecutionDetails {
        request_id: "req-001".to_string(),
        capability_id: "cap%011".to_string(), // Using % to ensure proper encoding
        args_hash: [0x11; 32],
        result_hash: [0x22; 32],
        success: true,
        result_message: Some("test".to_string()),
        duration_ns: 1_000_000,
    }
}

/// Constructs tool execution details without result message for golden vector.
#[must_use]
pub fn construct_tool_execution_details_no_message() -> ToolExecutionDetails {
    ToolExecutionDetails {
        request_id: "req-001".to_string(),
        capability_id: "cap%011".to_string(),
        args_hash: [0x11; 32],
        result_hash: [0x22; 32],
        success: false,
        result_message: None,
        duration_ns: 1_000_000,
    }
}

/// Constructs a tool execution receipt for golden vector.
#[must_use]
pub fn construct_receipt_tool_execution() -> ToolReceipt {
    // Note: We need to construct the receipt manually to get exact values
    // because the builder computes unsigned_bytes_hash
    let details = ToolExecutionDetails {
        request_id: "req-001".to_string(),
        capability_id: "cap%011".to_string(),
        args_hash: [0x11; 32],
        result_hash: [0x22; 32],
        success: true,
        result_message: None,
        duration_ns: 1_000_000,
    };

    ToolReceipt {
        kind: ReceiptKind::ToolExecution,
        episode_id: EpisodeId::new("ep00001").unwrap(),
        envelope_hash: [0xaa; 32],
        policy_hash: [0xbb; 32],
        canonicalizer_id: CanonicalizerId::apm2_proto_v1(),
        canonicalizer_version: 1,
        evidence_refs: vec![],
        timestamp_ns: 1_704_067_200_000_000_000, // 2024-01-01 00:00:00 UTC
        unsigned_bytes_hash: [0x00; 32],         // Placeholder - will be recomputed
        tool_execution_details: Some(details),
        signature: None,
        signer_identity: None,
    }
}

/// Constructs an episode start receipt for golden vector.
#[must_use]
pub fn construct_receipt_episode_start() -> ToolReceipt {
    ToolReceipt {
        kind: ReceiptKind::EpisodeStart,
        episode_id: EpisodeId::new("ep00002").unwrap(),
        envelope_hash: [0xaa; 32],
        policy_hash: [0xbb; 32],
        canonicalizer_id: CanonicalizerId::apm2_proto_v1(),
        canonicalizer_version: 1,
        evidence_refs: vec![],
        timestamp_ns: 1_234_567_890_123_456_789,
        unsigned_bytes_hash: [0xcc; 32],
        tool_execution_details: None,
        signature: None,
        signer_identity: None,
    }
}

/// Constructs a receipt with unsorted evidence refs for golden vector.
///
/// This tests that `canonical_bytes` sorts evidence refs.
#[must_use]
pub fn construct_receipt_sorted_evidence_refs() -> ToolReceipt {
    ToolReceipt {
        kind: ReceiptKind::EpisodeStart,
        episode_id: EpisodeId::new("ep00003").unwrap(),
        envelope_hash: [0xaa; 32],
        policy_hash: [0xbb; 32],
        canonicalizer_id: CanonicalizerId::apm2_proto_v1(),
        canonicalizer_version: 1,
        // Intentionally unsorted - canonical_bytes should sort these
        evidence_refs: vec![[0xff; 32], [0x00; 32], [0x88; 32]],
        timestamp_ns: 5_000_000_000,
        unsigned_bytes_hash: [0xdd; 32],
        tool_execution_details: None,
        signature: None,
        signer_identity: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ReceiptBuilder, SignerIdentity};

    /// Verify encoding matches expected bytes.
    fn verify_encoding(bytes: &[u8], vector: &GoldenVector) {
        let actual_hex = hex::encode(bytes);
        let actual_hash = hex::encode(blake3::hash(bytes).as_bytes());

        // Print for debugging when updating vectors
        eprintln!("Vector: {}", vector.name);
        eprintln!("  Contract: {}", vector.contract);
        eprintln!("  Actual bytes: {actual_hex}");
        eprintln!("  Actual hash:  {actual_hash}");
        eprintln!("  Expected bytes: {}", vector.expected_bytes);
        eprintln!("  Expected hash:  {}", vector.expected_hash);

        // Verify bytes match
        assert_eq!(
            actual_hex, vector.expected_bytes,
            "Bytes mismatch for {}: got {actual_hex}, expected {}",
            vector.name, vector.expected_bytes
        );

        // Verify hash matches
        assert_eq!(
            actual_hash, vector.expected_hash,
            "Hash mismatch for {}: got {actual_hash}, expected {}",
            vector.name, vector.expected_hash
        );
    }

    // ========================================================================
    // ToolExecutionDetails golden tests
    // ========================================================================

    #[test]
    fn test_golden_tool_execution_details() {
        let details = construct_tool_execution_details();
        let bytes = details.canonical_bytes();
        verify_encoding(&bytes, &TOOL_EXECUTION_DETAILS_VECTOR);
    }

    #[test]
    fn test_golden_tool_execution_details_no_message() {
        let details = construct_tool_execution_details_no_message();
        let bytes = details.canonical_bytes();
        verify_encoding(&bytes, &TOOL_EXECUTION_DETAILS_NO_MESSAGE_VECTOR);
    }

    // ========================================================================
    // ToolReceipt golden tests
    // ========================================================================

    #[test]
    fn test_golden_receipt_tool_execution() {
        let receipt = construct_receipt_tool_execution();
        let bytes = receipt.canonical_bytes();
        verify_encoding(&bytes, &RECEIPT_TOOL_EXECUTION_VECTOR);
    }

    #[test]
    fn test_golden_receipt_episode_start() {
        let receipt = construct_receipt_episode_start();
        let bytes = receipt.canonical_bytes();
        verify_encoding(&bytes, &RECEIPT_EPISODE_START_VECTOR);
    }

    #[test]
    fn test_golden_receipt_sorted_evidence_refs() {
        let receipt = construct_receipt_sorted_evidence_refs();
        let bytes = receipt.canonical_bytes();
        verify_encoding(&bytes, &RECEIPT_SORTED_EVIDENCE_REFS_VECTOR);
    }

    // ========================================================================
    // Stability tests
    // ========================================================================

    /// Verify that encoding is stable across multiple runs.
    #[test]
    fn test_encoding_stability() {
        for _ in 0..10 {
            let receipt1 = construct_receipt_episode_start();
            let receipt2 = construct_receipt_episode_start();

            let bytes1 = receipt1.canonical_bytes();
            let bytes2 = receipt2.canonical_bytes();

            assert_eq!(bytes1, bytes2, "Encoding should be stable");
        }
    }

    /// Verify that unsorted evidence refs produce sorted canonical bytes.
    #[test]
    fn test_canonical_bytes_sorts_evidence_refs() {
        // Create receipt with unsorted evidence refs
        let receipt_unsorted = ToolReceipt {
            kind: ReceiptKind::EpisodeStart,
            episode_id: EpisodeId::new("ep").unwrap(),
            envelope_hash: [0xab; 32],
            policy_hash: [0xcd; 32],
            canonicalizer_id: CanonicalizerId::apm2_proto_v1(),
            canonicalizer_version: 1,
            evidence_refs: vec![[0xff; 32], [0x00; 32], [0x88; 32]],
            timestamp_ns: 1000,
            unsigned_bytes_hash: [0xef; 32],
            tool_execution_details: None,
            signature: None,
            signer_identity: None,
        };

        // Create receipt with sorted evidence refs
        let receipt_sorted = ToolReceipt {
            kind: ReceiptKind::EpisodeStart,
            episode_id: EpisodeId::new("ep").unwrap(),
            envelope_hash: [0xab; 32],
            policy_hash: [0xcd; 32],
            canonicalizer_id: CanonicalizerId::apm2_proto_v1(),
            canonicalizer_version: 1,
            evidence_refs: vec![[0x00; 32], [0x88; 32], [0xff; 32]],
            timestamp_ns: 1000,
            unsigned_bytes_hash: [0xef; 32],
            tool_execution_details: None,
            signature: None,
            signer_identity: None,
        };

        // Canonical bytes should be identical
        assert_eq!(
            receipt_unsorted.canonical_bytes(),
            receipt_sorted.canonical_bytes(),
            "canonical_bytes must sort evidence refs regardless of insertion order"
        );
    }

    /// Property test: digest changes when any significant field changes.
    #[test]
    fn test_digest_changes_on_field_change() {
        let base = construct_receipt_episode_start();
        let base_bytes = base.canonical_bytes();
        let base_hash = blake3::hash(&base_bytes);

        // Change episode_id
        {
            let mut modified = construct_receipt_episode_start();
            modified.episode_id = EpisodeId::new("ep00099").unwrap();
            assert_ne!(
                blake3::hash(&modified.canonical_bytes()),
                base_hash,
                "Hash should change when episode_id changes"
            );
        }

        // Change envelope_hash
        {
            let mut modified = construct_receipt_episode_start();
            modified.envelope_hash = [0xfe; 32];
            assert_ne!(
                blake3::hash(&modified.canonical_bytes()),
                base_hash,
                "Hash should change when envelope_hash changes"
            );
        }

        // Change timestamp
        {
            let mut modified = construct_receipt_episode_start();
            modified.timestamp_ns = 9_999_999;
            assert_ne!(
                blake3::hash(&modified.canonical_bytes()),
                base_hash,
                "Hash should change when timestamp_ns changes"
            );
        }
    }

    /// Verify signature is excluded but `signer_identity` is included in
    /// canonical bytes.
    #[test]
    fn test_signature_excluded_but_signer_identity_included() {
        let receipt_unsigned = construct_receipt_episode_start();

        // Only add signature (not signer_identity)
        let mut receipt_with_sig_only = construct_receipt_episode_start();
        receipt_with_sig_only.signature = Some([0xab; 64]);

        // Signature alone should not change canonical bytes
        assert_eq!(
            receipt_unsigned.canonical_bytes(),
            receipt_with_sig_only.canonical_bytes(),
            "signature must be excluded from canonical bytes"
        );

        // Add signer_identity - this SHOULD change canonical bytes (for cryptographic
        // binding)
        let mut receipt_with_signer = construct_receipt_episode_start();
        receipt_with_signer.signer_identity = Some(SignerIdentity {
            public_key: [0x12; 32],
            identity: "test-signer".to_string(),
        });

        assert_ne!(
            receipt_unsigned.canonical_bytes(),
            receipt_with_signer.canonical_bytes(),
            "signer_identity must be INCLUDED in canonical bytes for cryptographic binding"
        );
    }

    /// Verify that builder produces correct receipts.
    #[test]
    fn test_builder_produces_valid_receipt() {
        let receipt = ReceiptBuilder::for_episode_start(EpisodeId::new("ep-test").unwrap())
            .with_envelope([0xaa; 32])
            .with_policy([0xbb; 32])
            .with_timestamp(1_000_000_000)
            .build()
            .unwrap();

        // Verify unsigned_bytes_hash is computed correctly
        assert_eq!(receipt.unsigned_bytes_hash, receipt.digest());

        // Verify the receipt validates
        assert!(receipt.validate().is_ok());
    }

    /// Verify receipt roundtrip through JSON preserves canonical bytes.
    #[test]
    fn test_serde_preserves_canonical_bytes() {
        let original = construct_receipt_episode_start();
        let original_bytes = original.canonical_bytes();

        let json = serde_json::to_string(&original).unwrap();
        let restored: ToolReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(
            restored.canonical_bytes(),
            original_bytes,
            "canonical bytes must be preserved through JSON roundtrip"
        );
    }
}
