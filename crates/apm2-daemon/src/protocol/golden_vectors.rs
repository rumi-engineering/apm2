//! Golden test vectors for protocol message determinism verification.
//!
//! This module contains golden vectors that verify the deterministic encoding
//! of protocol messages. Each vector consists of:
#![allow(clippy::doc_markdown, clippy::wildcard_imports)]
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
//! - **Signature stability**: Verify that signed messages can be verified after
//!   serialization/deserialization cycles
//! - **Cross-platform consistency**: Ensure wire format is consistent
//!   regardless of compilation target
//!
//! # Contract References
//!
//! - AD-DAEMON-003: Protobuf as primary wire encoding
//! - AD-VERIFY-001: Deterministic Protobuf serialization (canonical_bytes)
//! - CTR-1602: Serialization formats must be versioned and endianness-specified
//!
//! # Updating Vectors
//!
//! When message definitions change:
//! 1. Update the message construction in the vector
//! 2. Run tests to get new expected values
//! 3. Verify changes are intentional (breaking change = new protocol version)
//! 4. Update expected bytes and hashes

use super::messages::*;

/// A golden test vector.
pub struct GoldenVector {
    /// Human-readable name for the vector.
    pub name: &'static str,
    /// Contract reference (e.g., "CTR-PROTO-001").
    pub contract: &'static str,
    /// Expected BLAKE3 hash of the canonical bytes (hex-encoded).
    pub expected_hash: &'static str,
    /// Expected canonical bytes (hex-encoded).
    pub expected_bytes: &'static str,
}

// ============================================================================
// CTR-PROTO-001: Handshake vectors
// ============================================================================

/// Golden vector for Hello message.
pub const HELLO_VECTOR: GoldenVector = GoldenVector {
    name: "hello_basic",
    contract: "CTR-PROTO-001",
    expected_hash: "3b7c963c1668f2a5995bf989d220c87549c12c44700ca8b06f03f2703f734374",
    expected_bytes: "0801120a0a08617074322d636c69",
};

/// Golden vector for HelloAck message.
pub const HELLO_ACK_VECTOR: GoldenVector = GoldenVector {
    name: "hello_ack_basic",
    contract: "CTR-PROTO-001",
    expected_hash: "bea788528787654c4beb230e2711425f0ded7012e863645b55d53bfa018d6ac0",
    expected_bytes: "0a0e0a0561706d326412056170692e31",
};

// ============================================================================
// CTR-PROTO-002: Episode Control vectors
// ============================================================================

/// Golden vector for CreateEpisode message.
pub const CREATE_EPISODE_VECTOR: GoldenVector = GoldenVector {
    name: "create_episode_basic",
    contract: "CTR-PROTO-002",
    expected_hash: "cf8580043564938be43de8f1ca986d786f632e76743d577cd4d454a95f75e7cc",
    expected_bytes: "0a20abababababababababababababababababababababababababababababababab",
};

/// Golden vector for EpisodeCreated message.
pub const EPISODE_CREATED_VECTOR: GoldenVector = GoldenVector {
    name: "episode_created_basic",
    contract: "CTR-PROTO-002",
    expected_hash: "a1b1d3486f22ecdd8c389b2a9d94c1deb73e43811f1ff26bd5bf886b2f2135f2",
    expected_bytes: "0a05657030303112087365737330303031",
};

/// Golden vector for StopEpisode message.
pub const STOP_EPISODE_VECTOR: GoldenVector = GoldenVector {
    name: "stop_episode_goal_satisfied",
    contract: "CTR-PROTO-002",
    expected_hash: "ae39a625b8386234ba9e2344891d7526f78f54efdfeb54f6e689b88b8e303c8b",
    expected_bytes: "0a0565703030311001",
};

// ============================================================================
// CTR-PROTO-003: I/O vectors
// ============================================================================

/// Golden vector for StreamOutput message (stdout).
pub const STREAM_OUTPUT_STDOUT_VECTOR: GoldenVector = GoldenVector {
    name: "stream_output_stdout",
    contract: "CTR-PROTO-003",
    expected_hash: "035d7e3540bc18b09f277346a73421fea6a74999170ec415b7a417d615d73387",
    expected_bytes: "0a0548656c6c6f18012080c2d72f",
};

/// Golden vector for SendInput message.
pub const SEND_INPUT_VECTOR: GoldenVector = GoldenVector {
    name: "send_input_basic",
    contract: "CTR-PROTO-003",
    expected_hash: "773e3abe827c064c923395906f510a28888c3f0277324786d95654554ac46c96",
    expected_bytes: "0a056570303031120474657374",
};

// ============================================================================
// CTR-PROTO-004: Tool Mediation vectors
// ============================================================================

/// Golden vector for ToolRequest message.
pub const TOOL_REQUEST_VECTOR: GoldenVector = GoldenVector {
    name: "tool_request_file_read",
    contract: "CTR-PROTO-004",
    expected_hash: "3e2cb501948efa50fd28a0d878f4c6070ebc68a24cbca7b5b3532ca1c10e7fcd",
    expected_bytes: "0a05657030303112067265713030311a0966696c655f726561642210000000000000000000000000000000002a200000000000000000000000000000000000000000000000000000000000000000",
};

/// Golden vector for ToolDecision message (allow).
pub const TOOL_DECISION_ALLOW_VECTOR: GoldenVector = GoldenVector {
    name: "tool_decision_allow",
    contract: "CTR-PROTO-004",
    expected_hash: "cd812b374c510c222261136fbdfd8ca196834b6b7f5b33b6f7ca13a7681c1643",
    expected_bytes: "0a06726571303031222000000000000000000000000000000000000000000000000000000000000000002a06086410011832",
};

// ============================================================================
// CTR-PROTO-005: Telemetry vectors
// ============================================================================

/// Golden vector for TelemetryFrame message.
pub const TELEMETRY_FRAME_VECTOR: GoldenVector = GoldenVector {
    name: "telemetry_frame_basic",
    contract: "CTR-PROTO-005",
    expected_hash: "76590b18df24a797b7a5cf69e5e9c425fd29ad3aa12dfa9eedfa331183e8ecad",
    expected_bytes: "0a05657030303110011880c2d72f20c0843d28808040",
};

/// Golden vector for TelemetryPolicy message.
pub const TELEMETRY_POLICY_VECTOR: GoldenVector = GoldenVector {
    name: "telemetry_policy_basic",
    contract: "CTR-PROTO-005",
    expected_hash: "e42087ea4c97774a83af4139440792b69ac99915caa791c55a1781e3d9e0b789",
    expected_bytes: "08e80712160a0b6370752e70657263656e74110000000000005940",
};

// ============================================================================
// CTR-PROTO-006: Receipt and Evidence vectors
// ============================================================================

/// Golden vector for Receipt message.
pub const RECEIPT_VECTOR: GoldenVector = GoldenVector {
    name: "receipt_tool_execution",
    contract: "CTR-PROTO-006",
    expected_hash: "8d0d38966c11eb1f2496e1f1b901fd2c6c22f4ef4654e5dbe526f42079d0c156",
    expected_bytes: "2a20cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd3220abababababababababababababababababababababababababababababababab",
};

/// Golden vector for PublishEvidence message.
pub const PUBLISH_EVIDENCE_VECTOR: GoldenVector = GoldenVector {
    name: "publish_evidence_pty_transcript",
    contract: "CTR-PROTO-006",
    expected_hash: "9efa64570fd5702e3ff46f43003016cefc13914115731cdbeccffed3059d32ea",
    expected_bytes: "0a20abababababababababababababababababababababababababababababababab10011802",
};

/// Golden vector for EvidencePinned message.
pub const EVIDENCE_PINNED_VECTOR: GoldenVector = GoldenVector {
    name: "evidence_pinned_basic",
    contract: "CTR-PROTO-006",
    expected_hash: "c12257748cadff0e09534e497c51c1c95309b8f23b2dcf2872617ac15af288ad",
    expected_bytes: "0a20cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd1211706f6c696379207669006c6174696f6e001a0b6465666563743030313132",
};

// ============================================================================
// Helper functions
// ============================================================================

/// Constructs the Hello message for the golden vector.
#[must_use]
pub fn construct_hello_vector() -> Hello {
    Hello::new(1).with_client_info("apt2-cli", "")
}

/// Constructs the HelloAck message for the golden vector.
#[must_use]
pub fn construct_hello_ack_vector() -> HelloAck {
    HelloAck::new().with_server_info("apm2d", "api.1")
}

/// Constructs the CreateEpisode message for the golden vector.
#[must_use]
pub fn construct_create_episode_vector() -> CreateEpisode {
    CreateEpisode {
        envelope_hash: vec![0xab; 32],
    }
}

/// Constructs the EpisodeCreated message for the golden vector.
#[must_use]
pub fn construct_episode_created_vector() -> EpisodeCreated {
    EpisodeCreated {
        episode_id: "ep001".to_string(),
        session_id: "sess0001".to_string(),
    }
}

/// Constructs the StopEpisode message for the golden vector.
#[must_use]
pub fn construct_stop_episode_vector() -> StopEpisode {
    StopEpisode {
        episode_id: "ep001".to_string(),
        reason: StopReason::GoalSatisfied.into(),
    }
}

/// Constructs the StreamOutput message for the golden vector.
#[must_use]
pub fn construct_stream_output_vector() -> StreamOutput {
    StreamOutput::stdout(b"Hello".to_vec(), 1, 100_000_000)
}

/// Constructs the SendInput message for the golden vector.
#[must_use]
pub fn construct_send_input_vector() -> SendInput {
    SendInput {
        episode_id: "ep001".to_string(),
        data: b"test".to_vec(),
    }
}

/// Constructs the ToolRequest message for the golden vector.
#[must_use]
pub fn construct_tool_request_vector() -> ToolRequest {
    ToolRequest {
        episode_id: "ep001".to_string(),
        request_id: "req001".to_string(),
        tool: "file_read".to_string(),
        dedupe_key: vec![0x00; 16],
        args_hash: vec![0x00; 32],
        inline_args: None,
    }
}

/// Constructs the ToolDecision message for the golden vector.
#[must_use]
pub fn construct_tool_decision_vector() -> ToolDecision {
    ToolDecision {
        request_id: "req001".to_string(),
        decision: DecisionType::Allow.into(),
        rule_id: None,
        policy_hash: vec![0x00; 32],
        budget_delta: Some(BudgetDelta::new(100, 1, 50)),
    }
}

/// Constructs the TelemetryFrame message for the golden vector.
#[must_use]
pub fn construct_telemetry_frame_vector() -> TelemetryFrame {
    TelemetryFrame::new("ep001", 1, 100_000_000)
        .with_cpu_ns(1_000_000)
        .with_mem_rss_bytes(1024 * 1024)
}

/// Constructs the TelemetryPolicy message for the golden vector.
#[must_use]
pub fn construct_telemetry_policy_vector() -> TelemetryPolicy {
    TelemetryPolicy {
        sample_period_ms: 1000,
        promote_triggers: vec![PromoteTrigger {
            metric: "cpu.percent".to_string(),
            threshold: 100.0,
        }],
        ring_buffer_limits: None,
    }
}

/// Constructs the Receipt message for the golden vector.
#[must_use]
pub fn construct_receipt_vector() -> Receipt {
    Receipt::new(ReceiptKind::ToolExecution)
        .with_envelope_hash(vec![0xab; 32])
        .with_policy_hash(vec![0xcd; 32])
}

/// Constructs the PublishEvidence message for the golden vector.
#[must_use]
pub fn construct_publish_evidence_vector() -> PublishEvidence {
    PublishEvidence {
        artifact_hash: vec![0xab; 32],
        kind: EvidenceKind::PtyTranscript.into(),
        retention_hint: RetentionHint::Standard.into(),
    }
}

/// Constructs the EvidencePinned message for the golden vector.
#[must_use]
pub fn construct_evidence_pinned_vector() -> EvidencePinned {
    EvidencePinned {
        artifact_hash: vec![0xcd; 32],
        reason: "policy vi\0lation\0".to_string(),
        defect_id: Some("defect00112".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    /// Verify encoding matches expected bytes (update expected when
    /// intentionally changing format).
    fn verify_encoding<M: Message>(message: &M, vector: &GoldenVector) {
        let bytes = message.encode_to_vec();
        let actual_hex = hex::encode(&bytes);
        let actual_hash = hex::encode(blake3::hash(&bytes).as_bytes());

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

    #[test]
    fn test_golden_hello() {
        let msg = construct_hello_vector();
        verify_encoding(&msg, &HELLO_VECTOR);
    }

    #[test]
    fn test_golden_hello_ack() {
        let msg = construct_hello_ack_vector();
        verify_encoding(&msg, &HELLO_ACK_VECTOR);
    }

    #[test]
    fn test_golden_create_episode() {
        let msg = construct_create_episode_vector();
        verify_encoding(&msg, &CREATE_EPISODE_VECTOR);
    }

    #[test]
    fn test_golden_episode_created() {
        let msg = construct_episode_created_vector();
        verify_encoding(&msg, &EPISODE_CREATED_VECTOR);
    }

    #[test]
    fn test_golden_stop_episode() {
        let msg = construct_stop_episode_vector();
        verify_encoding(&msg, &STOP_EPISODE_VECTOR);
    }

    #[test]
    fn test_golden_stream_output() {
        let msg = construct_stream_output_vector();
        verify_encoding(&msg, &STREAM_OUTPUT_STDOUT_VECTOR);
    }

    #[test]
    fn test_golden_send_input() {
        let msg = construct_send_input_vector();
        verify_encoding(&msg, &SEND_INPUT_VECTOR);
    }

    #[test]
    fn test_golden_tool_request() {
        let msg = construct_tool_request_vector();
        verify_encoding(&msg, &TOOL_REQUEST_VECTOR);
    }

    #[test]
    fn test_golden_tool_decision() {
        let msg = construct_tool_decision_vector();
        verify_encoding(&msg, &TOOL_DECISION_ALLOW_VECTOR);
    }

    #[test]
    fn test_golden_telemetry_frame() {
        let msg = construct_telemetry_frame_vector();
        verify_encoding(&msg, &TELEMETRY_FRAME_VECTOR);
    }

    #[test]
    fn test_golden_telemetry_policy() {
        let msg = construct_telemetry_policy_vector();
        verify_encoding(&msg, &TELEMETRY_POLICY_VECTOR);
    }

    #[test]
    fn test_golden_receipt() {
        let msg = construct_receipt_vector();
        verify_encoding(&msg, &RECEIPT_VECTOR);
    }

    #[test]
    fn test_golden_publish_evidence() {
        let msg = construct_publish_evidence_vector();
        verify_encoding(&msg, &PUBLISH_EVIDENCE_VECTOR);
    }

    #[test]
    fn test_golden_evidence_pinned() {
        let msg = construct_evidence_pinned_vector();
        verify_encoding(&msg, &EVIDENCE_PINNED_VECTOR);
    }

    /// Verify that encoding is stable across multiple runs.
    #[test]
    fn test_encoding_stability() {
        for _ in 0..10 {
            let msg1 = construct_hello_vector();
            let msg2 = construct_hello_vector();

            let bytes1 = msg1.encode_to_vec();
            let bytes2 = msg2.encode_to_vec();

            assert_eq!(bytes1, bytes2, "Encoding should be stable");
        }
    }

    /// Verify that decode-encode roundtrip preserves bytes.
    #[test]
    fn test_roundtrip_stability() {
        let original = construct_receipt_vector();
        let bytes1 = original.encode_to_vec();

        let decoded = Receipt::decode(bytes1.as_slice()).expect("decode failed");
        let bytes2 = decoded.encode_to_vec();

        assert_eq!(bytes1, bytes2, "Roundtrip should preserve bytes");
    }
}
