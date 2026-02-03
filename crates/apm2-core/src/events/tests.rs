//! Tests for kernel event schemas.

use prost::Message;
use prost_types::Timestamp;

use super::*;

/// Test that session started events can be roundtrip encoded/decoded.
#[test]
fn test_session_started_roundtrip() {
    let started = SessionStarted {
        session_id: "session-123".to_string(),
        actor_id: "actor-456".to_string(),
        adapter_type: "claude-code".to_string(),
        work_id: "work-789".to_string(),
        lease_id: "lease-012".to_string(),
        entropy_budget: 10_000,
        resume_cursor: 0,
        restart_attempt: 0,
        // HTF time envelope reference (RFC-0016): not yet populated.
        time_envelope_ref: None,
        // Episode ID (RFC-0018, TCK-00306): empty for non-episode sessions.
        episode_id: String::new(),
    };

    let session_event = SessionEvent {
        event: Some(session_event::Event::Started(started)),
    };

    let kernel_event = KernelEvent {
        sequence: 1,
        previous_hash: vec![0u8; 32],
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        actor_id: "actor-456".to_string(),
        session_id: "session-123".to_string(),
        signature: vec![],
        schema_version: 1,
        payload: Some(kernel_event::Payload::Session(session_event)),
    };

    // Encode
    let bytes = kernel_event.encode_to_vec();

    // Decode
    let decoded = KernelEvent::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.sequence, 1);
    assert_eq!(decoded.actor_id, "actor-456");
    assert_eq!(decoded.session_id, "session-123");

    // Verify payload
    match decoded.payload {
        Some(kernel_event::Payload::Session(session)) => match session.event {
            Some(session_event::Event::Started(started)) => {
                assert_eq!(started.session_id, "session-123");
                assert_eq!(started.entropy_budget, 10_000);
            },
            _ => panic!("expected SessionStarted"),
        },
        _ => panic!("expected Session payload"),
    }
}

/// Test that work events can be roundtrip encoded/decoded.
#[test]
fn test_work_opened_roundtrip() {
    let opened = WorkOpened {
        work_id: "work-123".to_string(),
        work_type: "TICKET".to_string(),
        spec_snapshot_hash: vec![1, 2, 3, 4],
        requirement_ids: vec!["REQ-0001".to_string(), "REQ-0002".to_string()],
        parent_work_ids: vec![],
    };

    let work_event = WorkEvent {
        event: Some(work_event::Event::Opened(opened)),
    };

    let kernel_event = KernelEvent {
        sequence: 2,
        payload: Some(kernel_event::Payload::Work(work_event)),
        ..Default::default()
    };

    let bytes = kernel_event.encode_to_vec();
    let decoded = KernelEvent::decode(bytes.as_slice()).expect("decode failed");

    match decoded.payload {
        Some(kernel_event::Payload::Work(work)) => match work.event {
            Some(work_event::Event::Opened(opened)) => {
                assert_eq!(opened.work_id, "work-123");
                assert_eq!(opened.requirement_ids.len(), 2);
            },
            _ => panic!("expected WorkOpened"),
        },
        _ => panic!("expected Work payload"),
    }
}

/// Test that tool events can be roundtrip encoded/decoded.
#[test]
fn test_tool_requested_roundtrip() {
    let requested = ToolRequested {
        request_id: "req-001".to_string(),
        session_id: "session-123".to_string(),
        tool_name: "file_read".to_string(),
        tool_args_hash: vec![0xab; 32],
        dedupe_key: "key-123".to_string(),
        // Episode ID (RFC-0018, TCK-00306): empty for non-episode sessions.
        episode_id: String::new(),
    };

    let tool_event = ToolEvent {
        event: Some(tool_event::Event::Requested(requested)),
    };

    let kernel_event = KernelEvent {
        sequence: 3,
        payload: Some(kernel_event::Payload::Tool(tool_event)),
        ..Default::default()
    };

    let bytes = kernel_event.encode_to_vec();
    let decoded = KernelEvent::decode(bytes.as_slice()).expect("decode failed");

    match decoded.payload {
        Some(kernel_event::Payload::Tool(tool)) => match tool.event {
            Some(tool_event::Event::Requested(req)) => {
                assert_eq!(req.tool_name, "file_read");
                assert_eq!(req.tool_args_hash.len(), 32);
            },
            _ => panic!("expected ToolRequested"),
        },
        _ => panic!("expected Tool payload"),
    }
}

/// Test that lease events can be roundtrip encoded/decoded.
#[test]
fn test_lease_issued_roundtrip() {
    let issued = LeaseIssued {
        lease_id: "lease-001".to_string(),
        work_id: "work-123".to_string(),
        actor_id: "actor-456".to_string(),
        issued_at: 1_700_000_000,
        expires_at: 1_700_003_600,
        registrar_signature: vec![0xde; 64],
        // HTF time envelope reference (RFC-0016): not yet populated.
        time_envelope_ref: None,
        // Tick-based timing (RFC-0016 HTF).
        issued_at_tick: 1000,
        expires_at_tick: 5000,
        tick_rate_hz: 1_000_000,
    };

    let lease_event = LeaseEvent {
        event: Some(lease_event::Event::Issued(issued)),
    };

    let kernel_event = KernelEvent {
        sequence: 4,
        payload: Some(kernel_event::Payload::Lease(lease_event)),
        ..Default::default()
    };

    let bytes = kernel_event.encode_to_vec();
    let decoded = KernelEvent::decode(bytes.as_slice()).expect("decode failed");

    match decoded.payload {
        Some(kernel_event::Payload::Lease(lease)) => match lease.event {
            Some(lease_event::Event::Issued(issued)) => {
                assert_eq!(issued.lease_id, "lease-001");
                assert_eq!(issued.expires_at, 1_700_003_600);
            },
            _ => panic!("expected LeaseIssued"),
        },
        _ => panic!("expected Lease payload"),
    }
}

/// Test that policy events can be roundtrip encoded/decoded.
#[test]
fn test_policy_violation_roundtrip() {
    let violation = PolicyViolation {
        session_id: "session-123".to_string(),
        violation_type: "UNAUTHORIZED_TOOL".to_string(),
        rule_id: "rule-001".to_string(),
        details: "Attempted to use shell_exec without permission".to_string(),
    };

    let policy_event = PolicyEvent {
        event: Some(policy_event::Event::Violation(violation)),
    };

    let kernel_event = KernelEvent {
        sequence: 5,
        payload: Some(kernel_event::Payload::Policy(policy_event)),
        ..Default::default()
    };

    let bytes = kernel_event.encode_to_vec();
    let decoded = KernelEvent::decode(bytes.as_slice()).expect("decode failed");

    match decoded.payload {
        Some(kernel_event::Payload::Policy(policy)) => match policy.event {
            Some(policy_event::Event::Violation(v)) => {
                assert_eq!(v.violation_type, "UNAUTHORIZED_TOOL");
            },
            _ => panic!("expected PolicyViolation"),
        },
        _ => panic!("expected Policy payload"),
    }
}

/// Test that adjudication events can be roundtrip encoded/decoded.
#[test]
fn test_adjudication_requested_roundtrip() {
    let requested = AdjudicationRequested {
        adjudication_id: "adj-001".to_string(),
        work_id: "work-123".to_string(),
        request_type: "BOUNDED_CHOICE".to_string(),
        options: vec!["Option A".to_string(), "Option B".to_string()],
        deadline: 1_700_003_600,
        fallback_policy: "default_to_first".to_string(),
    };

    let adj_event = AdjudicationEvent {
        event: Some(adjudication_event::Event::Requested(requested)),
    };

    let kernel_event = KernelEvent {
        sequence: 6,
        payload: Some(kernel_event::Payload::Adjudication(adj_event)),
        ..Default::default()
    };

    let bytes = kernel_event.encode_to_vec();
    let decoded = KernelEvent::decode(bytes.as_slice()).expect("decode failed");

    match decoded.payload {
        Some(kernel_event::Payload::Adjudication(adj)) => match adj.event {
            Some(adjudication_event::Event::Requested(req)) => {
                assert_eq!(req.options.len(), 2);
            },
            _ => panic!("expected AdjudicationRequested"),
        },
        _ => panic!("expected Adjudication payload"),
    }
}

/// Test that evidence events can be roundtrip encoded/decoded.
#[test]
fn test_evidence_published_roundtrip() {
    let published = EvidencePublished {
        evidence_id: "evid-001".to_string(),
        work_id: "work-123".to_string(),
        category: "TEST_RESULTS".to_string(),
        artifact_hash: vec![0xca; 32],
        verification_command_ids: vec!["cmd-001".to_string()],
        classification: "INTERNAL".to_string(),
        artifact_size: 1024,
        metadata: vec!["key=value".to_string()],
        // HTF time envelope reference (RFC-0016): not yet populated.
        time_envelope_ref: None,
    };

    let evidence_event = EvidenceEvent {
        event: Some(evidence_event::Event::Published(published)),
    };

    let kernel_event = KernelEvent {
        sequence: 7,
        payload: Some(kernel_event::Payload::Evidence(evidence_event)),
        ..Default::default()
    };

    let bytes = kernel_event.encode_to_vec();
    let decoded = KernelEvent::decode(bytes.as_slice()).expect("decode failed");

    match decoded.payload {
        Some(kernel_event::Payload::Evidence(ev)) => match ev.event {
            Some(evidence_event::Event::Published(pub_ev)) => {
                assert_eq!(pub_ev.evidence_id, "evid-001");
            },
            _ => panic!("expected EvidencePublished"),
        },
        _ => panic!("expected Evidence payload"),
    }
}

/// Test that encoding produces deterministic bytes (canonical encoding).
/// This is critical for signature verification.
#[test]
fn test_canonical_encoding_deterministic() {
    let event = KernelEvent {
        sequence: 100,
        previous_hash: vec![1, 2, 3, 4, 5],
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 500,
        }),
        actor_id: "actor-test".to_string(),
        session_id: "session-test".to_string(),
        signature: vec![0u8; 64],
        schema_version: 1,
        payload: Some(kernel_event::Payload::Session(SessionEvent {
            event: Some(session_event::Event::Progress(SessionProgress {
                session_id: "session-test".to_string(),
                progress_sequence: 42,
                progress_type: "HEARTBEAT".to_string(),
                entropy_consumed: 500,
                // Episode ID (RFC-0018, TCK-00306): empty for non-episode sessions.
                episode_id: String::new(),
            })),
        })),
    };

    // Encode multiple times
    let bytes1 = event.encode_to_vec();
    let bytes2 = event.encode_to_vec();
    let bytes3 = event.encode_to_vec();

    // All encodings must be identical
    assert_eq!(bytes1, bytes2);
    assert_eq!(bytes2, bytes3);

    // Decode and re-encode must produce identical bytes
    let decoded = KernelEvent::decode(bytes1.as_slice()).expect("decode failed");
    let bytes4 = decoded.encode_to_vec();
    assert_eq!(bytes1, bytes4);
}

/// Test that repeated fields are ordered correctly after canonicalization.
#[test]
fn test_repeated_fields_ordering() {
    use super::Canonicalize;

    let mut opened = WorkOpened {
        work_id: "work-1".to_string(),
        work_type: "TICKET".to_string(),
        spec_snapshot_hash: vec![],
        requirement_ids: vec![
            "REQ-C".to_string(),
            "REQ-A".to_string(),
            "REQ-B".to_string(),
        ],
        parent_work_ids: vec!["parent-2".to_string(), "parent-1".to_string()],
    };

    // Before canonicalization: protobuf preserves insertion order
    let bytes_before = opened.encode_to_vec();
    let decoded_before = WorkOpened::decode(bytes_before.as_slice()).expect("decode failed");
    assert_eq!(decoded_before.requirement_ids[0], "REQ-C");
    assert_eq!(decoded_before.requirement_ids[1], "REQ-A");
    assert_eq!(decoded_before.requirement_ids[2], "REQ-B");

    // After canonicalization: fields are sorted
    opened.canonicalize();

    assert_eq!(opened.requirement_ids[0], "REQ-A");
    assert_eq!(opened.requirement_ids[1], "REQ-B");
    assert_eq!(opened.requirement_ids[2], "REQ-C");
    assert_eq!(opened.parent_work_ids[0], "parent-1");
    assert_eq!(opened.parent_work_ids[1], "parent-2");

    // Encoding canonicalized data produces deterministic bytes
    let bytes_after = opened.encode_to_vec();
    let decoded_after = WorkOpened::decode(bytes_after.as_slice()).expect("decode failed");
    assert_eq!(decoded_after.requirement_ids[0], "REQ-A");
    assert_eq!(decoded_after.requirement_ids[1], "REQ-B");
    assert_eq!(decoded_after.requirement_ids[2], "REQ-C");
}

/// Test empty/default event encoding.
#[test]
fn test_empty_event_encoding() {
    let event = KernelEvent::default();
    let bytes = event.encode_to_vec();

    // Default event should encode to minimal bytes
    let decoded = KernelEvent::decode(bytes.as_slice()).expect("decode failed");
    assert_eq!(decoded.sequence, 0);
    assert!(decoded.previous_hash.is_empty());
    assert!(decoded.payload.is_none());
}

/// Test large payload handling.
#[test]
fn test_large_payload() {
    let large_hash = vec![0xffu8; 1024]; // 1KB hash (unrealistic but tests limits)

    let opened = WorkOpened {
        work_id: "work-large".to_string(),
        work_type: "TICKET".to_string(),
        spec_snapshot_hash: large_hash,
        requirement_ids: (0..100).map(|i| format!("REQ-{i:04}")).collect(),
        parent_work_ids: vec![],
    };

    let bytes = opened.encode_to_vec();
    let decoded = WorkOpened::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.spec_snapshot_hash.len(), 1024);
    assert_eq!(decoded.requirement_ids.len(), 100);
}

/// Test all session event variants.
#[test]
fn test_all_session_variants() {
    // SessionStarted
    let started = SessionEvent {
        event: Some(session_event::Event::Started(SessionStarted::default())),
    };
    let _ = started.encode_to_vec();

    // SessionProgress
    let progress = SessionEvent {
        event: Some(session_event::Event::Progress(SessionProgress::default())),
    };
    let _ = progress.encode_to_vec();

    // SessionTerminated
    let terminated = SessionEvent {
        event: Some(session_event::Event::Terminated(
            SessionTerminated::default(),
        )),
    };
    let _ = terminated.encode_to_vec();

    // SessionQuarantined
    let quarantined = SessionEvent {
        event: Some(session_event::Event::Quarantined(
            SessionQuarantined::default(),
        )),
    };
    let _ = quarantined.encode_to_vec();
}

/// Test all work event variants.
#[test]
fn test_all_work_variants() {
    let opened = WorkEvent {
        event: Some(work_event::Event::Opened(WorkOpened::default())),
    };
    let _ = opened.encode_to_vec();

    let transitioned = WorkEvent {
        event: Some(work_event::Event::Transitioned(WorkTransitioned::default())),
    };
    let _ = transitioned.encode_to_vec();

    let completed = WorkEvent {
        event: Some(work_event::Event::Completed(WorkCompleted::default())),
    };
    let _ = completed.encode_to_vec();

    let aborted = WorkEvent {
        event: Some(work_event::Event::Aborted(WorkAborted::default())),
    };
    let _ = aborted.encode_to_vec();
}

/// Test all tool event variants.
#[test]
fn test_all_tool_variants() {
    let requested = ToolEvent {
        event: Some(tool_event::Event::Requested(ToolRequested::default())),
    };
    let _ = requested.encode_to_vec();

    let decided = ToolEvent {
        event: Some(tool_event::Event::Decided(ToolDecided::default())),
    };
    let _ = decided.encode_to_vec();

    let executed = ToolEvent {
        event: Some(tool_event::Event::Executed(ToolExecuted::default())),
    };
    let _ = executed.encode_to_vec();
}

/// Test all lease event variants.
#[test]
fn test_all_lease_variants() {
    let issued = LeaseEvent {
        event: Some(lease_event::Event::Issued(LeaseIssued::default())),
    };
    let _ = issued.encode_to_vec();

    let renewed = LeaseEvent {
        event: Some(lease_event::Event::Renewed(LeaseRenewed::default())),
    };
    let _ = renewed.encode_to_vec();

    let released = LeaseEvent {
        event: Some(lease_event::Event::Released(LeaseReleased::default())),
    };
    let _ = released.encode_to_vec();

    let expired = LeaseEvent {
        event: Some(lease_event::Event::Expired(LeaseExpired::default())),
    };
    let _ = expired.encode_to_vec();

    let conflict = LeaseEvent {
        event: Some(lease_event::Event::Conflict(LeaseConflict::default())),
    };
    let _ = conflict.encode_to_vec();
}

/// Test all policy event variants.
#[test]
fn test_all_policy_variants() {
    let loaded = PolicyEvent {
        event: Some(policy_event::Event::Loaded(PolicyLoaded::default())),
    };
    let _ = loaded.encode_to_vec();

    let violation = PolicyEvent {
        event: Some(policy_event::Event::Violation(PolicyViolation::default())),
    };
    let _ = violation.encode_to_vec();

    let exceeded = PolicyEvent {
        event: Some(policy_event::Event::BudgetExceeded(
            BudgetExceeded::default(),
        )),
    };
    let _ = exceeded.encode_to_vec();
}

/// Test all adjudication event variants.
#[test]
fn test_all_adjudication_variants() {
    let requested = AdjudicationEvent {
        event: Some(adjudication_event::Event::Requested(
            AdjudicationRequested::default(),
        )),
    };
    let _ = requested.encode_to_vec();

    let vote = AdjudicationEvent {
        event: Some(adjudication_event::Event::Vote(AdjudicationVote::default())),
    };
    let _ = vote.encode_to_vec();

    let resolved = AdjudicationEvent {
        event: Some(adjudication_event::Event::Resolved(
            AdjudicationResolved::default(),
        )),
    };
    let _ = resolved.encode_to_vec();

    let timeout = AdjudicationEvent {
        event: Some(adjudication_event::Event::Timeout(
            AdjudicationTimeout::default(),
        )),
    };
    let _ = timeout.encode_to_vec();
}

/// Test all evidence event variants.
#[test]
fn test_all_evidence_variants() {
    let published = EvidenceEvent {
        event: Some(evidence_event::Event::Published(
            EvidencePublished::default(),
        )),
    };
    let _ = published.encode_to_vec();

    let gate_receipt = EvidenceEvent {
        event: Some(evidence_event::Event::GateReceipt(
            GateReceiptGenerated::default(),
        )),
    };
    let _ = gate_receipt.encode_to_vec();
}
