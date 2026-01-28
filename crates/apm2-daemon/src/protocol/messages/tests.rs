//! Tests for protocol message types.

use prost::Message;

use super::*;

// ============================================================================
// Roundtrip tests
// ============================================================================

#[test]
fn test_hello_roundtrip() {
    let hello = Hello::new(1)
        .with_client_info("apm2-cli", "0.3.0")
        .with_capability("episode.create")
        .with_capability("episode.attach");

    let bytes = hello.encode_to_vec();
    let decoded = Hello::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.protocol_version, 1);
    assert_eq!(decoded.client_info.as_ref().unwrap().name, "apm2-cli");
    assert_eq!(decoded.client_info.as_ref().unwrap().version, "0.3.0");
    assert_eq!(decoded.requested_caps.len(), 2);
}

#[test]
fn test_hello_ack_roundtrip() {
    let ack = HelloAck::new()
        .with_server_info("apm2d", "0.3.0")
        .with_granted_cap("episode.create")
        .with_policy_hash(vec![0u8; 32]);

    let bytes = ack.encode_to_vec();
    let decoded = HelloAck::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.server_info.as_ref().unwrap().name, "apm2d");
    assert_eq!(decoded.granted_caps.len(), 1);
    assert_eq!(decoded.policy_hash.len(), 32);
}

#[test]
fn test_create_episode_roundtrip() {
    let create = CreateEpisode {
        envelope_hash: vec![0xab; 32],
    };

    let bytes = create.encode_to_vec();
    let decoded = CreateEpisode::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.envelope_hash.len(), 32);
    assert!(decoded.envelope_hash.iter().all(|&b| b == 0xab));
}

#[test]
fn test_episode_created_roundtrip() {
    let created = EpisodeCreated {
        episode_id: "ep-123".to_string(),
        session_id: "sess-456".to_string(),
    };

    let bytes = created.encode_to_vec();
    let decoded = EpisodeCreated::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.episode_id, "ep-123");
    assert_eq!(decoded.session_id, "sess-456");
}

#[test]
fn test_stop_episode_roundtrip() {
    let stop = StopEpisode {
        episode_id: "ep-123".to_string(),
        reason: StopReason::GoalSatisfied.into(),
    };

    let bytes = stop.encode_to_vec();
    let decoded = StopEpisode::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.episode_id, "ep-123");
    assert_eq!(decoded.reason, StopReason::GoalSatisfied as i32);
}

#[test]
fn test_stream_output_roundtrip() {
    let output = StreamOutput::stdout(b"Hello, world!".to_vec(), 1, 1_700_000_000);

    let bytes = output.encode_to_vec();
    let decoded = StreamOutput::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.chunk, b"Hello, world!");
    assert_eq!(decoded.kind, StreamKind::Stdout as i32);
    assert_eq!(decoded.seq, 1);
}

#[test]
fn test_tool_request_roundtrip() {
    let request = ToolRequest {
        episode_id: "ep-123".to_string(),
        request_id: "req-001".to_string(),
        tool: "file_read".to_string(),
        dedupe_key: vec![0xde; 16],
        args_hash: vec![0xab; 32],
        inline_args: Some(b"{\"path\":\"/foo/bar\"}".to_vec()),
    };

    let bytes = request.encode_to_vec();
    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.tool, "file_read");
    assert_eq!(decoded.dedupe_key.len(), 16);
    assert!(decoded.inline_args.is_some());
}

#[test]
fn test_tool_decision_roundtrip() {
    let decision = ToolDecision {
        request_id: "req-001".to_string(),
        decision: DecisionType::Allow.into(),
        rule_id: Some("rule-001".to_string()),
        policy_hash: vec![0xca; 32],
        budget_delta: Some(BudgetDelta::new(100, 1, 50)),
    };

    let bytes = decision.encode_to_vec();
    let decoded = ToolDecision::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.decision, DecisionType::Allow as i32);
    assert_eq!(decoded.budget_delta.as_ref().unwrap().tokens, 100);
}

#[test]
fn test_telemetry_frame_roundtrip() {
    let frame = TelemetryFrame::new("ep-123", 42, 1_700_000_000)
        .with_cpu_ns(1_000_000)
        .with_mem_rss_bytes(1024 * 1024)
        .with_io_bytes(4096, 2048)
        .with_cgroup_stats(CgroupStats {
            cpu_usage_usec: 500_000,
            memory_current: 1024 * 1024,
            memory_max: 256 * 1024 * 1024,
        });

    let bytes = frame.encode_to_vec();
    let decoded = TelemetryFrame::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.episode_id, "ep-123");
    assert_eq!(decoded.seq, 42);
    assert_eq!(decoded.cpu_ns, 1_000_000);
    assert!(decoded.cgroup_stats.is_some());
}

#[test]
fn test_receipt_roundtrip() {
    let receipt = Receipt::new(ReceiptKind::ToolExecution)
        .with_envelope_hash(vec![0xab; 32])
        .with_policy_hash(vec![0xcd; 32])
        .with_evidence_ref(vec![0xef; 32]);

    let bytes = receipt.encode_to_vec();
    let decoded = Receipt::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.kind, ReceiptKind::ToolExecution as i32);
    assert_eq!(decoded.envelope_hash.len(), 32);
    assert_eq!(decoded.evidence_refs.len(), 1);
}

#[test]
fn test_publish_evidence_roundtrip() {
    let publish = PublishEvidence {
        artifact_hash: vec![0xab; 32],
        kind: EvidenceKind::PtyTranscript.into(),
        retention_hint: RetentionHint::Standard.into(),
    };

    let bytes = publish.encode_to_vec();
    let decoded = PublishEvidence::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.kind, EvidenceKind::PtyTranscript as i32);
    assert_eq!(decoded.retention_hint, RetentionHint::Standard as i32);
}

// ============================================================================
// Canonicalization tests
// ============================================================================

#[test]
fn test_hello_canonicalize() {
    let mut hello = Hello::new(1)
        .with_capability("cap-z")
        .with_capability("cap-a")
        .with_capability("cap-m");

    hello.canonicalize();

    assert_eq!(hello.requested_caps, vec!["cap-a", "cap-m", "cap-z"]);
}

#[test]
fn test_hello_ack_canonicalize() {
    let mut ack = HelloAck::new()
        .with_granted_cap("cap-z")
        .with_granted_cap("cap-a")
        .with_granted_cap("cap-m");

    ack.canonicalize();

    assert_eq!(ack.granted_caps, vec!["cap-a", "cap-m", "cap-z"]);
}

#[test]
fn test_receipt_canonicalize() {
    let mut receipt = Receipt::new(ReceiptKind::EpisodeStart)
        .with_evidence_ref(vec![0xff; 32])
        .with_evidence_ref(vec![0x00; 32])
        .with_evidence_ref(vec![0xaa; 32]);

    receipt.canonicalize();

    // Sorted by byte content
    assert_eq!(receipt.evidence_refs[0], vec![0x00; 32]);
    assert_eq!(receipt.evidence_refs[1], vec![0xaa; 32]);
    assert_eq!(receipt.evidence_refs[2], vec![0xff; 32]);
}

#[test]
fn test_episode_quarantined_canonicalize() {
    let mut quarantined = EpisodeQuarantined {
        episode_id: "ep-123".to_string(),
        reason: "policy violation".to_string(),
        evidence_pinned: vec![vec![0xff; 32], vec![0x00; 32], vec![0xaa; 32]],
    };

    quarantined.canonicalize();

    assert_eq!(quarantined.evidence_pinned[0], vec![0x00; 32]);
    assert_eq!(quarantined.evidence_pinned[1], vec![0xaa; 32]);
    assert_eq!(quarantined.evidence_pinned[2], vec![0xff; 32]);
}

#[test]
fn test_compaction_completed_canonicalize() {
    let mut compaction = CompactionCompleted {
        summary_receipt_hash: vec![0xab; 32],
        tombstoned_hashes: vec![vec![0xff; 32], vec![0x00; 32], vec![0xaa; 32]],
    };

    compaction.canonicalize();

    assert_eq!(compaction.tombstoned_hashes[0], vec![0x00; 32]);
    assert_eq!(compaction.tombstoned_hashes[1], vec![0xaa; 32]);
    assert_eq!(compaction.tombstoned_hashes[2], vec![0xff; 32]);
}

#[test]
fn test_telemetry_policy_canonicalize() {
    let mut policy = TelemetryPolicy {
        sample_period_ms: 1000,
        promote_triggers: vec![
            PromoteTrigger {
                metric: "cpu.percent".to_string(),
                threshold: 90.0,
            },
            PromoteTrigger {
                metric: "memory.percent".to_string(),
                threshold: 80.0,
            },
            PromoteTrigger {
                metric: "io.latency_ms".to_string(),
                threshold: 100.0,
            },
        ],
        ring_buffer_limits: None,
    };

    policy.canonicalize();

    assert_eq!(policy.promote_triggers[0].metric, "cpu.percent");
    assert_eq!(policy.promote_triggers[1].metric, "io.latency_ms");
    assert_eq!(policy.promote_triggers[2].metric, "memory.percent");
}

// ============================================================================
// Canonical bytes tests
// ============================================================================

#[test]
fn test_receipt_canonical_bytes_excludes_signature() {
    let mut receipt = Receipt::new(ReceiptKind::ToolExecution)
        .with_envelope_hash(vec![0xab; 32])
        .with_policy_hash(vec![0xcd; 32]);

    // Get canonical bytes without signature
    let canonical1 = receipt.canonical_bytes();

    // Add signature
    receipt.signature = vec![0xee; 64];
    receipt.issuer_signature = Some(vec![0xff; 64]);

    // Canonical bytes should still exclude signature
    let canonical2 = receipt.canonical_bytes();

    assert_eq!(
        canonical1, canonical2,
        "canonical bytes should exclude signature"
    );
}

#[test]
fn test_receipt_canonical_bytes_deterministic() {
    let receipt = Receipt::new(ReceiptKind::EpisodeStop)
        .with_envelope_hash(vec![0xab; 32])
        .with_policy_hash(vec![0xcd; 32])
        .with_evidence_ref(vec![0xef; 32]);

    let bytes1 = receipt.canonical_bytes();
    let bytes2 = receipt.canonical_bytes();
    let bytes3 = receipt.canonical_bytes();

    assert_eq!(bytes1, bytes2);
    assert_eq!(bytes2, bytes3);
}

#[test]
fn test_receipt_compute_unsigned_bytes_hash() {
    let receipt = Receipt::new(ReceiptKind::Gate)
        .with_envelope_hash(vec![0xab; 32])
        .with_policy_hash(vec![0xcd; 32])
        .compute_unsigned_bytes_hash();

    // Hash should be 32 bytes (BLAKE3)
    assert_eq!(receipt.unsigned_bytes_hash.len(), 32);
    assert!(!receipt.unsigned_bytes_hash.iter().all(|&b| b == 0));
}

// ============================================================================
// Encoding determinism tests
// ============================================================================

#[test]
fn test_encoding_deterministic() {
    let frame = TelemetryFrame::new("ep-123", 1, 1_700_000_000)
        .with_cpu_ns(500_000)
        .with_mem_rss_bytes(1024 * 1024);

    let bytes1 = frame.encode_to_vec();
    let bytes2 = frame.encode_to_vec();

    assert_eq!(bytes1, bytes2);

    // Decode and re-encode
    let decoded = TelemetryFrame::decode(bytes1.as_slice()).expect("decode failed");
    let bytes3 = decoded.encode_to_vec();

    assert_eq!(bytes1, bytes3);
}

#[test]
fn test_all_stop_reasons() {
    let reasons = [
        StopReason::Unspecified,
        StopReason::GoalSatisfied,
        StopReason::BudgetExhausted,
        StopReason::PolicyViolation,
        StopReason::UserRequest,
        StopReason::HarnessCrash,
        StopReason::AdapterFailure,
    ];

    for reason in reasons {
        let stop = StopEpisode {
            episode_id: "ep-test".to_string(),
            reason: reason.into(),
        };
        let bytes = stop.encode_to_vec();
        let decoded = StopEpisode::decode(bytes.as_slice()).expect("decode failed");
        assert_eq!(decoded.reason, reason as i32);
    }
}

#[test]
fn test_all_receipt_kinds() {
    let kinds = [
        ReceiptKind::ToolExecution,
        ReceiptKind::EpisodeStart,
        ReceiptKind::EpisodeStop,
        ReceiptKind::Gate,
        ReceiptKind::Telemetry,
        ReceiptKind::Compaction,
        ReceiptKind::StopOrder,
    ];

    for kind in kinds {
        let receipt = Receipt::new(kind);
        let bytes = receipt.encode_to_vec();
        let decoded = Receipt::decode(bytes.as_slice()).expect("decode failed");
        assert_eq!(decoded.kind, kind as i32);
    }
}

#[test]
fn test_all_evidence_kinds() {
    let kinds = [
        EvidenceKind::Unspecified,
        EvidenceKind::PtyTranscript,
        EvidenceKind::ToolIo,
        EvidenceKind::TelemetryRaw,
        EvidenceKind::AdapterFailure,
        EvidenceKind::IncidentSnapshot,
    ];

    for kind in kinds {
        let evidence = PublishEvidence {
            artifact_hash: vec![0u8; 32],
            kind: kind.into(),
            retention_hint: RetentionHint::Standard.into(),
        };
        let bytes = evidence.encode_to_vec();
        let decoded = PublishEvidence::decode(bytes.as_slice()).expect("decode failed");
        assert_eq!(decoded.kind, kind as i32);
    }
}

// ============================================================================
// Empty/default tests
// ============================================================================

#[test]
fn test_empty_message_encoding() {
    let hello = Hello::default();
    let bytes = hello.encode_to_vec();
    let decoded = Hello::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.protocol_version, 0);
    assert!(decoded.client_info.is_none());
    assert!(decoded.requested_caps.is_empty());
}

#[test]
fn test_empty_receipt_encoding() {
    let receipt = Receipt::default();
    let bytes = receipt.encode_to_vec();
    let decoded = Receipt::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.kind, 0);
    assert!(decoded.signature.is_empty());
    assert!(decoded.evidence_refs.is_empty());
}

// ============================================================================
// Enum conversion tests
// ============================================================================

#[test]
fn test_stop_reason_from_str() {
    assert_eq!(
        StopReason::from_str_name("GOAL_SATISFIED"),
        Some(StopReason::GoalSatisfied)
    );
    assert_eq!(
        StopReason::from_str_name("BUDGET_EXHAUSTED"),
        Some(StopReason::BudgetExhausted)
    );
    assert_eq!(StopReason::from_str_name("INVALID"), None);
}

#[test]
fn test_stop_reason_as_str() {
    assert_eq!(StopReason::GoalSatisfied.as_str_name(), "GOAL_SATISFIED");
    assert_eq!(
        StopReason::BudgetExhausted.as_str_name(),
        "BUDGET_EXHAUSTED"
    );
}

#[test]
fn test_receipt_kind_from_str() {
    assert_eq!(
        ReceiptKind::from_str_name("TOOL_EXECUTION"),
        Some(ReceiptKind::ToolExecution)
    );
    assert_eq!(
        ReceiptKind::from_str_name("EPISODE_START"),
        Some(ReceiptKind::EpisodeStart)
    );
}

#[test]
fn test_stream_kind_conversion() {
    assert_eq!(
        StreamKind::from_str_name("STDOUT"),
        Some(StreamKind::Stdout)
    );
    assert_eq!(
        StreamKind::from_str_name("STDERR"),
        Some(StreamKind::Stderr)
    );
    assert_eq!(StreamKind::Stdout.as_str_name(), "STDOUT");
}
