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

/// Per AD-VERIFY-001: `canonical_bytes` must produce identical output
/// regardless of the order in which repeated fields were added.
#[test]
fn test_receipt_canonical_bytes_sorts_unsorted_evidence_refs() {
    // Create two receipts with evidence_refs added in different orders
    let receipt_ab = Receipt::new(ReceiptKind::EpisodeStop)
        .with_envelope_hash(vec![0xab; 32])
        .with_policy_hash(vec![0xcd; 32])
        .with_evidence_ref(vec![0x00; 32]) // A first
        .with_evidence_ref(vec![0xff; 32]); // B second

    let receipt_ba = Receipt::new(ReceiptKind::EpisodeStop)
        .with_envelope_hash(vec![0xab; 32])
        .with_policy_hash(vec![0xcd; 32])
        .with_evidence_ref(vec![0xff; 32]) // B first
        .with_evidence_ref(vec![0x00; 32]); // A second

    // canonical_bytes must be identical because it sorts evidence_refs
    assert_eq!(
        receipt_ab.canonical_bytes(),
        receipt_ba.canonical_bytes(),
        "canonical_bytes must produce identical output regardless of insertion order"
    );
}

/// Test that `TelemetryPolicy` sorts triggers by (metric, threshold) for total
/// ordering
#[test]
#[allow(clippy::float_cmp)] // Exact comparison is intentional for these test values
fn test_telemetry_policy_canonicalize_total_ordering() {
    // Same metric but different thresholds - should have stable ordering
    let mut policy = TelemetryPolicy {
        sample_period_ms: 1000,
        promote_triggers: vec![
            PromoteTrigger {
                metric: "cpu.percent".to_string(),
                threshold: 90.0,
            },
            PromoteTrigger {
                metric: "cpu.percent".to_string(),
                threshold: 80.0,
            },
            PromoteTrigger {
                metric: "cpu.percent".to_string(),
                threshold: 95.0,
            },
        ],
        ring_buffer_limits: None,
    };

    policy.canonicalize();

    // Should be sorted by threshold ascending (80, 90, 95)
    assert_eq!(policy.promote_triggers[0].threshold, 80.0);
    assert_eq!(policy.promote_triggers[1].threshold, 90.0);
    assert_eq!(policy.promote_triggers[2].threshold, 95.0);
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

// ============================================================================
// Bounded decoding tests (CTR-1603, RSK-1601)
// ============================================================================

#[test]
fn test_bounded_decode_within_limits() {
    let hello = Hello::new(1)
        .with_client_info("test", "1.0")
        .with_capability("cap1");

    let bytes = hello.encode_to_vec();
    let config = DecodeConfig::default();

    let decoded = Hello::decode_bounded(&bytes, &config).expect("decode should succeed");
    assert_eq!(decoded.protocol_version, 1);
    assert_eq!(decoded.requested_caps.len(), 1);
}

#[test]
fn test_bounded_decode_rejects_oversized_message() {
    // Create a message that exceeds our configured limit
    let config = DecodeConfig::new(100, 1000); // Only allow 100 bytes

    // Create a message larger than 100 bytes
    let mut hello = Hello::new(1).with_client_info("test-client-with-a-long-name", "1.0.0");
    for i in 0..10 {
        hello = hello.with_capability(format!("capability-{i}"));
    }

    let bytes = hello.encode_to_vec();
    assert!(bytes.len() > 100, "message should be larger than limit");

    let result = Hello::decode_bounded(&bytes, &config);
    assert!(
        matches!(
            result,
            Err(DecodeError::MessageTooLarge { size, max })
            if size == bytes.len() && max == 100
        ),
        "should reject oversized message: {result:?}"
    );
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn test_bounded_decode_rejects_too_many_repeated_elements() {
    // Create a Receipt with many evidence_refs
    let mut receipt = Receipt::new(ReceiptKind::ToolExecution)
        .with_envelope_hash(vec![0xab; 32])
        .with_policy_hash(vec![0xcd; 32]);

    // Add more evidence_refs than allowed
    for i in 0u8..100 {
        receipt = receipt.with_evidence_ref(vec![i; 32]);
    }

    let bytes = receipt.encode_to_vec();

    // Configure to only allow 50 repeated elements
    let config = DecodeConfig::new(64 * 1024 * 1024, 50);

    let result = Receipt::decode_bounded(&bytes, &config);
    assert!(
        matches!(
            result,
            Err(DecodeError::RepeatedFieldTooLarge { field, count, max })
            if field == "evidence_refs" && count == 100 && max == 50
        ),
        "should reject message with too many repeated elements: {result:?}"
    );
}

#[test]
fn test_bounded_decode_default_config() {
    let frame = TelemetryFrame::new("ep-123", 1, 1000).with_cpu_ns(500);

    let bytes = frame.encode_to_vec();
    let decoded = TelemetryFrame::decode_bounded_default(&bytes).expect("decode should succeed");

    assert_eq!(decoded.episode_id, "ep-123");
    assert_eq!(decoded.cpu_ns, 500);
}

#[test]
fn test_bounded_decode_handshake_config() {
    let hello = Hello::new(1).with_client_info("test", "1.0");

    let bytes = hello.encode_to_vec();
    let config = DecodeConfig::handshake();

    let decoded = Hello::decode_bounded(&bytes, &config).expect("decode should succeed");
    assert_eq!(decoded.protocol_version, 1);
}

#[test]
fn test_bounded_decode_handshake_rejects_large_message() {
    // Create a message larger than handshake limit (64 KiB)
    let config = DecodeConfig::handshake();

    // Create a very large fake "message" buffer
    let large_buffer = vec![0u8; 65 * 1024]; // 65 KiB, exceeds 64 KiB limit

    let result = Hello::decode_bounded(&large_buffer, &config);
    assert!(
        matches!(
            result,
            Err(DecodeError::MessageTooLarge { size, max })
            if size == 65 * 1024 && max == 64 * 1024
        ),
        "handshake config should reject 65KiB message: {result:?}"
    );
}

#[test]
fn test_bounded_decode_hello_ack_repeated_field() {
    let mut ack = HelloAck::new();
    for i in 0..100 {
        ack = ack.with_granted_cap(format!("cap-{i}"));
    }

    let bytes = ack.encode_to_vec();

    // Allow message size but limit repeated fields to 50
    let config = DecodeConfig::new(64 * 1024 * 1024, 50);

    let result = HelloAck::decode_bounded(&bytes, &config);
    assert!(
        matches!(
            result,
            Err(DecodeError::RepeatedFieldTooLarge { field, count, max })
            if field == "granted_caps" && count == 100 && max == 50
        ),
        "should reject HelloAck with too many granted_caps: {result:?}"
    );
}

#[test]
fn test_bounded_decode_telemetry_policy_repeated_field() {
    let mut policy = TelemetryPolicy {
        sample_period_ms: 1000,
        promote_triggers: Vec::new(),
        ring_buffer_limits: None,
    };

    // Add many triggers
    for i in 0i32..100 {
        policy.promote_triggers.push(PromoteTrigger {
            metric: format!("metric-{i}"),
            threshold: f64::from(i),
        });
    }

    let bytes = policy.encode_to_vec();

    // Allow message size but limit repeated fields to 50
    let config = DecodeConfig::new(64 * 1024 * 1024, 50);

    let result = TelemetryPolicy::decode_bounded(&bytes, &config);
    assert!(
        matches!(
            result,
            Err(DecodeError::RepeatedFieldTooLarge { field, count, max })
            if field == "promote_triggers" && count == 100 && max == 50
        ),
        "should reject TelemetryPolicy with too many triggers: {result:?}"
    );
}

#[test]
fn test_bounded_decode_simple_message_no_repeated() {
    // Test that simple messages (no repeated fields) work correctly
    let frame = TelemetryFrame::new("ep-test", 42, 1000)
        .with_cpu_ns(100)
        .with_mem_rss_bytes(1024);

    let bytes = frame.encode_to_vec();
    let config = DecodeConfig::new(1024, 10); // Reasonable limits

    let decoded = TelemetryFrame::decode_bounded(&bytes, &config).expect("decode should succeed");
    assert_eq!(decoded.episode_id, "ep-test");
    assert_eq!(decoded.seq, 42);
    assert_eq!(decoded.cpu_ns, 100);
}

#[test]
fn test_decode_error_display() {
    let err = DecodeError::MessageTooLarge { size: 100, max: 50 };
    assert!(err.to_string().contains("100"));
    assert!(err.to_string().contains("50"));

    let err = DecodeError::RepeatedFieldTooLarge {
        field: "evidence_refs",
        count: 200,
        max: 100,
    };
    assert!(err.to_string().contains("evidence_refs"));
    assert!(err.to_string().contains("200"));
    assert!(err.to_string().contains("100"));

    let err = DecodeError::Prost("invalid wire type".to_string());
    assert!(err.to_string().contains("invalid wire type"));
}

#[test]
fn test_decode_config_constants() {
    // Verify the default constants are reasonable
    assert_eq!(super::DEFAULT_MAX_MESSAGE_SIZE, 64 * 1024 * 1024);
    assert_eq!(super::DEFAULT_MAX_REPEATED_FIELD_COUNT, 100_000);

    let config = DecodeConfig::default();
    assert_eq!(config.max_message_size, 64 * 1024 * 1024);
    assert_eq!(config.max_repeated_field_count, 100_000);

    let handshake = DecodeConfig::handshake();
    assert_eq!(handshake.max_message_size, 64 * 1024);
    assert_eq!(handshake.max_repeated_field_count, 1_000);
}
