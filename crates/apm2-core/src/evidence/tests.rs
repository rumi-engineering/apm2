//! Integration tests for evidence module.

use crate::evidence::reducer::helpers;
use crate::evidence::{
    ContentAddressedStore, DataClassification, EvidenceCategory, EvidencePublisher,
    EvidenceReducer, MemoryCas,
};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

/// Creates a test event record with the given parameters.
fn make_event_record(event_type: &str, payload: Vec<u8>, timestamp: u64) -> EventRecord {
    EventRecord::with_timestamp(event_type, "session-001", "actor-001", payload, timestamp)
}

// ============================================================
// End-to-end publishing tests
// ============================================================

#[test]
fn test_publish_and_reduce_evidence() {
    let cas = MemoryCas::new();
    let publisher = EvidencePublisher::new(cas);
    let mut reducer = EvidenceReducer::new();

    // Publish an artifact
    let content = b"test results: all passed";
    let result = publisher
        .publish(
            "evid-001",
            "work-123",
            content,
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &["CMD-001".to_string()],
        )
        .unwrap();

    // Create and apply the event
    let payload = helpers::evidence_published_payload(
        "evid-001",
        "work-123",
        "TEST_RESULTS",
        result.artifact_hash.to_vec(),
        vec!["CMD-001".to_string()],
        "INTERNAL",
        content.len() as u64,
        vec![],
    );
    let event = make_event_record("evidence.published", payload, 1_000_000_000);
    let ctx = ReducerContext::new(1);

    reducer.apply(&event, &ctx).unwrap();

    // Verify state
    let state = reducer.state();
    assert_eq!(state.len(), 1);

    let evidence = state.get("evid-001").unwrap();
    assert_eq!(evidence.work_id, "work-123");
    assert_eq!(evidence.category, EvidenceCategory::TestResults);
    assert_eq!(evidence.artifact_hash, result.artifact_hash);
    assert_eq!(evidence.verification_command_ids, vec!["CMD-001"]);
    assert_eq!(evidence.classification, DataClassification::Internal);
    assert_eq!(evidence.artifact_size, content.len());

    // Verify content can be retrieved
    let retrieved = publisher.retrieve(&result.artifact_hash).unwrap();
    assert_eq!(retrieved, content);
}

#[test]
fn test_classification_preserved_in_reducer() {
    let mut reducer = EvidenceReducer::new();

    // Publish RESTRICTED evidence
    let payload = helpers::evidence_published_payload(
        "evid-001",
        "work-123",
        "SECURITY_SCANS",
        vec![1u8; 32],
        vec![],
        "RESTRICTED",
        512,
        vec!["scan_type=vulnerability".to_string()],
    );
    let event = make_event_record("evidence.published", payload, 1_000_000);
    reducer.apply(&event, &ReducerContext::new(1)).unwrap();

    // Verify classification is preserved
    let evidence = reducer.state().get("evid-001").unwrap();
    assert_eq!(evidence.classification, DataClassification::Restricted);
    assert_eq!(evidence.artifact_size, 512);
    assert!(evidence.requires_progressive_disclosure());
    assert_eq!(evidence.get_metadata("scan_type"), Some("vulnerability"));
}

#[test]
fn test_multiple_evidence_for_work() {
    let cas = MemoryCas::new();
    let publisher = EvidencePublisher::new(cas);
    let mut reducer = EvidenceReducer::new();

    // Publish multiple artifacts for the same work
    let results: Vec<_> = [
        ("evid-001", "test results", EvidenceCategory::TestResults),
        ("evid-002", "lint output", EvidenceCategory::LintReports),
        ("evid-003", "security scan", EvidenceCategory::SecurityScans),
    ]
    .iter()
    .map(|(id, content, category)| {
        let result = publisher
            .publish(
                id,
                "work-123",
                content.as_bytes(),
                *category,
                DataClassification::Internal,
                &[],
            )
            .unwrap();

        let payload = helpers::evidence_published_payload(
            id,
            "work-123",
            category.as_str(),
            result.artifact_hash.to_vec(),
            vec![],
            "INTERNAL",
            content.len() as u64,
            vec![],
        );
        (result, payload)
    })
    .collect();

    // Apply all events
    for (i, (_, payload)) in results.iter().enumerate() {
        let event = make_event_record("evidence.published", payload.clone(), i as u64);
        let ctx = ReducerContext::new(i as u64 + 1);
        reducer.apply(&event, &ctx).unwrap();
    }

    // Verify state
    let state = reducer.state();
    assert_eq!(state.len(), 3);
    assert_eq!(state.count_by_work("work-123"), 3);

    // Verify category indexing
    let test_results = state.get_by_work_and_category("work-123", EvidenceCategory::TestResults);
    assert_eq!(test_results.len(), 1);

    let lint_reports = state.get_by_work_and_category("work-123", EvidenceCategory::LintReports);
    assert_eq!(lint_reports.len(), 1);

    // Verify categories list
    let categories = state.categories_by_work("work-123");
    assert_eq!(categories.len(), 3);
}

#[test]
fn test_evidence_bundle_assembly() {
    let cas = MemoryCas::new();
    let publisher = EvidencePublisher::new(cas);
    let mut reducer = EvidenceReducer::new();

    // Publish artifacts
    for (id, content) in [("evid-001", "test"), ("evid-002", "lint")] {
        let result = publisher
            .publish(
                id,
                "work-123",
                content.as_bytes(),
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &[],
            )
            .unwrap();

        let payload = helpers::evidence_published_payload(
            id,
            "work-123",
            "TEST_RESULTS",
            result.artifact_hash.to_vec(),
            vec![],
            "INTERNAL",
            content.len() as u64,
            vec![],
        );
        let event = make_event_record("evidence.published", payload, 1_000_000);
        reducer.apply(&event, &ReducerContext::new(1)).unwrap();
    }

    // Generate gate receipt (triggers bundle assembly)
    let receipt_payload = helpers::gate_receipt_payload(
        "receipt-001",
        "gate-001",
        "work-123",
        "PASS",
        vec!["evid-001".to_string(), "evid-002".to_string()],
        vec![1, 2, 3], // signature
    );
    let receipt_event = make_event_record("evidence.gate_receipt", receipt_payload, 2_000_000);
    reducer
        .apply(&receipt_event, &ReducerContext::new(3))
        .unwrap();

    // Verify bundle was created
    let bundle = reducer.state().get_bundle("work-123").unwrap();
    assert_eq!(bundle.work_id, "work-123");
    assert_eq!(bundle.evidence_count(), 2);
    assert!(!bundle.is_empty());
    assert!(bundle.has_category(EvidenceCategory::TestResults));
}

// ============================================================
// CAS deduplication tests
// ============================================================

#[test]
fn test_cas_deduplication_across_works() {
    let cas = MemoryCas::new();
    let publisher = EvidencePublisher::new(cas.clone());

    let content = b"shared content";

    // Publish same content for different works
    let result1 = publisher
        .publish(
            "evid-001",
            "work-1",
            content,
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &[],
        )
        .unwrap();

    let result2 = publisher
        .publish(
            "evid-002",
            "work-2",
            content,
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &[],
        )
        .unwrap();

    // Same hash, but second is deduplicated
    assert_eq!(result1.artifact_hash, result2.artifact_hash);
    assert!(result1.is_new_content);
    assert!(!result2.is_new_content);

    // Only one copy in CAS
    assert_eq!(cas.len(), 1);
}

#[test]
fn test_cas_storage_full() {
    // Create a CAS with a very small limit (100 bytes)
    let cas = MemoryCas::with_max_size(100);

    // First store should succeed (50 bytes)
    let content1 = vec![1u8; 50];
    let result1 = cas.store(&content1);
    assert!(result1.is_ok());

    // Second store should also succeed (40 bytes, total 90)
    let content2 = vec![2u8; 40];
    let result2 = cas.store(&content2);
    assert!(result2.is_ok());

    // Third store should fail (would exceed 100 byte limit)
    let content3 = vec![3u8; 20];
    let result3 = cas.store(&content3);
    assert!(matches!(
        result3,
        Err(crate::evidence::CasError::StorageFull { .. })
    ));
}

// ============================================================
// Classification and progressive disclosure tests
// ============================================================

#[test]
fn test_classification_progressive_disclosure() {
    for (classification, requires_disclosure) in [
        (DataClassification::Public, false),
        (DataClassification::Internal, false),
        (DataClassification::Confidential, true),
        (DataClassification::Restricted, true),
    ] {
        assert_eq!(
            classification.requires_progressive_disclosure(),
            requires_disclosure,
            "Classification {classification:?} should require_progressive_disclosure = {requires_disclosure}"
        );
    }
}

#[test]
fn test_classification_retention_ordering() {
    // More sensitive data should have shorter retention
    let public_retention = DataClassification::Public.default_retention_days();
    let internal_retention = DataClassification::Internal.default_retention_days();
    let confidential_retention = DataClassification::Confidential.default_retention_days();
    let restricted_retention = DataClassification::Restricted.default_retention_days();

    assert!(public_retention > internal_retention);
    assert!(internal_retention > confidential_retention);
    assert!(confidential_retention > restricted_retention);
}

// ============================================================
// Category validation tests
// ============================================================

#[test]
fn test_category_requires_verification() {
    let verifiable = [
        EvidenceCategory::TestResults,
        EvidenceCategory::LintReports,
        EvidenceCategory::SecurityScans,
        EvidenceCategory::BuildArtifacts,
        EvidenceCategory::Benchmarks,
    ];

    let non_verifiable = [
        EvidenceCategory::ReviewRecords,
        EvidenceCategory::AuditLogs,
        EvidenceCategory::ConfigSnapshots,
        EvidenceCategory::Documentation,
        EvidenceCategory::DeploymentRecords,
    ];

    for category in verifiable {
        assert!(
            category.requires_verification(),
            "{category:?} should require verification"
        );
    }

    for category in non_verifiable {
        assert!(
            !category.requires_verification(),
            "{category:?} should not require verification"
        );
    }
}

// ============================================================
// Reducer error handling tests
// ============================================================

#[test]
fn test_reducer_rejects_duplicate_evidence_id() {
    let mut reducer = EvidenceReducer::new();

    let payload = helpers::evidence_published_payload(
        "evid-001",
        "work-123",
        "TEST_RESULTS",
        vec![0u8; 32],
        vec![],
        "INTERNAL",
        100,
        vec![],
    );

    // First event succeeds
    let event1 = make_event_record("evidence.published", payload.clone(), 1_000_000);
    reducer.apply(&event1, &ReducerContext::new(1)).unwrap();

    // Second event with same ID fails
    let event2 = make_event_record("evidence.published", payload, 2_000_000);
    let result = reducer.apply(&event2, &ReducerContext::new(2));

    assert!(result.is_err());
}

#[test]
fn test_reducer_rejects_empty_evidence_id() {
    let mut reducer = EvidenceReducer::new();

    let payload = helpers::evidence_published_payload(
        "", // empty
        "work-123",
        "TEST_RESULTS",
        vec![0u8; 32],
        vec![],
        "INTERNAL",
        100,
        vec![],
    );

    let event = make_event_record("evidence.published", payload, 1_000_000);
    let result = reducer.apply(&event, &ReducerContext::new(1));

    assert!(result.is_err());
}

#[test]
fn test_reducer_rejects_invalid_hash_size() {
    let mut reducer = EvidenceReducer::new();

    let payload = helpers::evidence_published_payload(
        "evid-001",
        "work-123",
        "TEST_RESULTS",
        vec![0u8; 16], // wrong size (should be 32)
        vec![],
        "INTERNAL",
        100,
        vec![],
    );

    let event = make_event_record("evidence.published", payload, 1_000_000);
    let result = reducer.apply(&event, &ReducerContext::new(1));

    assert!(result.is_err());
}

#[test]
fn test_reducer_ignores_non_evidence_events() {
    let mut reducer = EvidenceReducer::new();

    let event = EventRecord::new("session.started", "session-001", "actor-001", vec![1, 2, 3]);

    // Should not error on non-evidence events
    reducer.apply(&event, &ReducerContext::new(1)).unwrap();

    // State should be empty
    assert!(reducer.state().is_empty());
}

#[test]
fn test_reducer_reset() {
    let mut reducer = EvidenceReducer::new();

    let payload = helpers::evidence_published_payload(
        "evid-001",
        "work-123",
        "TEST_RESULTS",
        vec![0u8; 32],
        vec![],
        "INTERNAL",
        100,
        vec![],
    );

    let event = make_event_record("evidence.published", payload, 1_000_000);
    reducer.apply(&event, &ReducerContext::new(1)).unwrap();
    assert_eq!(reducer.state().len(), 1);

    reducer.reset();
    assert!(reducer.state().is_empty());
}

// ============================================================
// CAS boundary tests
// ============================================================

#[test]
fn test_cas_empty_content_rejected() {
    let cas = MemoryCas::new();
    let result = cas.store(b"");
    assert!(result.is_err());
}

#[test]
fn test_cas_hash_verification_on_retrieve() {
    let cas = MemoryCas::new();
    let content = b"test content";

    let result = cas.store(content).unwrap();

    // Retrieve should verify hash internally
    let retrieved = cas.retrieve(&result.hash).unwrap();
    assert_eq!(retrieved, content);
}

#[test]
fn test_cas_not_found() {
    let cas = MemoryCas::new();
    let fake_hash = [42u8; 32];

    let result = cas.retrieve(&fake_hash);
    assert!(result.is_err());
}

// ============================================================
// State query tests
// ============================================================

#[test]
fn test_state_get_by_work() {
    let mut reducer = EvidenceReducer::new();

    // Add evidence for work-1
    for id in ["evid-001", "evid-002"] {
        let payload = helpers::evidence_published_payload(
            id,
            "work-1",
            "TEST_RESULTS",
            vec![id.as_bytes()[5]; 32], // unique hash per evidence
            vec![],
            "INTERNAL",
            100,
            vec![],
        );
        let event = make_event_record("evidence.published", payload, 1_000_000);
        reducer.apply(&event, &ReducerContext::new(1)).unwrap();
    }

    // Add evidence for work-2
    let payload = helpers::evidence_published_payload(
        "evid-003",
        "work-2",
        "LINT_REPORTS",
        vec![3u8; 32],
        vec![],
        "INTERNAL",
        100,
        vec![],
    );
    let event = make_event_record("evidence.published", payload, 1_000_000);
    reducer.apply(&event, &ReducerContext::new(2)).unwrap();

    // Query by work
    let state = reducer.state();
    assert_eq!(state.get_by_work("work-1").len(), 2);
    assert_eq!(state.get_by_work("work-2").len(), 1);
    assert_eq!(state.get_by_work("work-3").len(), 0);
}

#[test]
fn test_state_get_by_category() {
    let mut reducer = EvidenceReducer::new();

    // Add test results
    for (id, hash_byte) in [("evid-001", 1u8), ("evid-002", 2u8)] {
        let payload = helpers::evidence_published_payload(
            id,
            "work-1",
            "TEST_RESULTS",
            vec![hash_byte; 32],
            vec![],
            "INTERNAL",
            100,
            vec![],
        );
        let event = make_event_record("evidence.published", payload, 1_000_000);
        reducer.apply(&event, &ReducerContext::new(1)).unwrap();
    }

    // Add lint report
    let payload = helpers::evidence_published_payload(
        "evid-003",
        "work-1",
        "LINT_REPORTS",
        vec![3u8; 32],
        vec![],
        "INTERNAL",
        100,
        vec![],
    );
    let event = make_event_record("evidence.published", payload, 1_000_000);
    reducer.apply(&event, &ReducerContext::new(2)).unwrap();

    let state = reducer.state();
    assert_eq!(
        state.get_by_category(EvidenceCategory::TestResults).len(),
        2
    );
    assert_eq!(
        state.get_by_category(EvidenceCategory::LintReports).len(),
        1
    );
    assert_eq!(
        state.get_by_category(EvidenceCategory::SecurityScans).len(),
        0
    );
}

// ============================================================
// Determinism tests
// ============================================================

#[test]
fn test_bundle_hash_is_deterministic() {
    // Create two reducers with same events in same order
    let mut reducer1 = EvidenceReducer::new();
    let mut reducer2 = EvidenceReducer::new();

    for (id, hash_byte) in [("evid-001", 1u8), ("evid-002", 2u8)] {
        let payload = helpers::evidence_published_payload(
            id,
            "work-123",
            "TEST_RESULTS",
            vec![hash_byte; 32],
            vec![],
            "INTERNAL",
            100,
            vec![],
        );
        let event = make_event_record("evidence.published", payload, 1_000_000);
        let ctx = ReducerContext::new(1);
        reducer1.apply(&event, &ctx).unwrap();
        reducer2.apply(&event, &ctx).unwrap();
    }

    // Generate gate receipts
    let receipt_payload = helpers::gate_receipt_payload(
        "receipt-001",
        "gate-001",
        "work-123",
        "PASS",
        vec!["evid-001".to_string(), "evid-002".to_string()],
        vec![1, 2, 3],
    );
    let receipt_event = make_event_record("evidence.gate_receipt", receipt_payload, 2_000_000);
    reducer1
        .apply(&receipt_event, &ReducerContext::new(3))
        .unwrap();
    reducer2
        .apply(&receipt_event, &ReducerContext::new(3))
        .unwrap();

    // Bundle hashes should be identical
    let bundle1 = reducer1.state().get_bundle("work-123").unwrap();
    let bundle2 = reducer2.state().get_bundle("work-123").unwrap();
    assert_eq!(bundle1.bundle_hash, bundle2.bundle_hash);
}
