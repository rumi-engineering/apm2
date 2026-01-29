//! E2E compaction and TTL tests for TCK-00177.
//!
//! This module tests the full compaction and TTL lifecycle including:
//! - TTL-based artifact expiration
//! - Artifact pinning prevents deletion
//! - Compaction produces valid tombstones and summaries
//! - Expired artifacts are evicted correctly
//!
//! # Test Approach
//!
//! These tests use the artifact, TTL, and compaction modules to verify:
//! 1. Expired artifacts are identified for eviction
//! 2. Pinned artifacts are protected from eviction
//! 3. Compaction produces valid receipts
//! 4. Tombstones correctly reference original artifacts
//!
//! # Contract References
//!
//! - TCK-00177: E2E evidence and receipt verification tests
//! - AD-EVID-002: Evidence retention and TTL
//! - REQ-EVID-003: Evidence compaction requirements
//!
//! # Test Coverage
//!
//! | Test ID        | Description                          |
//! |----------------|--------------------------------------|
//! | E2E-00177-03   | Compaction and TTL E2E               |
//! | UT-CP-001      | Expired artifacts evicted            |
//! | UT-CP-002      | Pinned artifacts protected           |
//! | UT-CP-003      | Compaction produces valid receipts   |
//! | UT-CP-004      | Tombstone references correct         |
//! | UT-CP-005      | Pin expiration scenarios             |

mod common;

use apm2_daemon::episode::EpisodeId;
use apm2_daemon::evidence::{
    ARCHIVAL_TTL_SECS, ArtifactKind, CompactionCounts, CompactionJob, CompactionStrategy,
    CompactionSummary, EPHEMERAL_TTL_SECS, EvidenceArtifact, EvidenceClass,
    MIN_COMPACTION_THRESHOLD_NS, PinReason, STANDARD_TTL_SECS, Tombstone, TombstoneList,
    TtlEnforcer, TtlEnforcerConfig,
};

// =============================================================================
// Test Helpers
// =============================================================================

/// Creates a test episode ID.
fn test_episode_id(suffix: &str) -> EpisodeId {
    EpisodeId::new(format!("e2e-compact-{suffix}")).expect("valid episode ID")
}

/// Computes BLAKE3 hash of content.
fn compute_hash(content: &[u8]) -> [u8; 32] {
    *blake3::hash(content).as_bytes()
}

/// Test timestamp base: 2024-01-01 00:00:00 UTC in nanoseconds.
const TEST_TIMESTAMP_NS: u64 = 1_704_067_200_000_000_000;

/// Creates a test artifact with specified class and creation time.
fn create_artifact(suffix: &str, class: EvidenceClass, created_at: u64) -> EvidenceArtifact {
    let content = format!("test content for {suffix}");
    let hash = compute_hash(content.as_bytes());
    EvidenceArtifact::from_content(hash, class, test_episode_id(suffix).as_str(), created_at)
        .expect("artifact creation should succeed")
}

// =============================================================================
// UT-CP-001: Expired Artifacts Evicted
// =============================================================================

/// Tests that unpinned artifacts expire after their TTL.
#[test]
fn test_unpinned_artifact_expires_after_ttl() {
    let artifact = create_artifact("ttl-001", EvidenceClass::Ephemeral, TEST_TIMESTAMP_NS);

    // Calculate expiration time (ephemeral = 1 hour)
    let expires_at = TEST_TIMESTAMP_NS + (EPHEMERAL_TTL_SECS * 1_000_000_000);

    // Should not be expired before TTL
    assert!(!artifact.is_expired(TEST_TIMESTAMP_NS));
    assert!(!artifact.is_expired(expires_at - 1));

    // Should be expired at and after TTL
    assert!(artifact.is_expired(expires_at));
    assert!(artifact.is_expired(expires_at + 1_000_000_000));
}

/// Tests that standard artifacts have correct TTL.
#[test]
fn test_standard_artifact_ttl() {
    let artifact = create_artifact("ttl-002", EvidenceClass::Standard, TEST_TIMESTAMP_NS);

    // Standard TTL is 7 days
    let seven_days_ns = STANDARD_TTL_SECS * 1_000_000_000;
    let expires_at = TEST_TIMESTAMP_NS + seven_days_ns;

    // Should not be expired before 7 days
    assert!(!artifact.is_expired(TEST_TIMESTAMP_NS + seven_days_ns - 1));

    // Should be expired at 7 days
    assert!(artifact.is_expired(expires_at));
}

/// Tests that archival artifacts have correct TTL.
#[test]
fn test_archival_artifact_ttl() {
    let artifact = create_artifact("ttl-003", EvidenceClass::Archival, TEST_TIMESTAMP_NS);

    // Archival TTL is 90 days
    let ninety_days_ns = ARCHIVAL_TTL_SECS * 1_000_000_000;
    let expires_at = TEST_TIMESTAMP_NS + ninety_days_ns;

    // Should not be expired before 90 days
    assert!(!artifact.is_expired(TEST_TIMESTAMP_NS + ninety_days_ns - 1));

    // Should be expired at 90 days
    assert!(artifact.is_expired(expires_at));
}

/// Tests remaining TTL calculation.
#[test]
fn test_remaining_ttl_calculation() {
    let artifact = create_artifact("ttl-004", EvidenceClass::Standard, TEST_TIMESTAMP_NS);

    // At creation, remaining TTL should equal full TTL
    assert_eq!(
        artifact.remaining_ttl_secs(TEST_TIMESTAMP_NS),
        STANDARD_TTL_SECS
    );

    // After one day, remaining TTL should decrease
    let one_day_ns = 24 * 3600 * 1_000_000_000;
    let one_day_later = TEST_TIMESTAMP_NS + one_day_ns;
    assert_eq!(
        artifact.remaining_ttl_secs(one_day_later),
        STANDARD_TTL_SECS - (24 * 3600)
    );

    // After expiration, remaining TTL should be 0
    let after_expiry = TEST_TIMESTAMP_NS + (STANDARD_TTL_SECS * 1_000_000_000) + 1;
    assert_eq!(artifact.remaining_ttl_secs(after_expiry), 0);
}

/// Tests `should_evict` for unpinned expired artifact.
#[test]
fn test_should_evict_expired_unpinned() {
    let artifact = create_artifact("evict-001", EvidenceClass::Ephemeral, TEST_TIMESTAMP_NS);

    // Before expiration
    assert!(!artifact.should_evict(TEST_TIMESTAMP_NS));

    // After expiration
    let after_expiry = TEST_TIMESTAMP_NS + (EPHEMERAL_TTL_SECS * 1_000_000_000);
    assert!(artifact.should_evict(after_expiry));
}

// =============================================================================
// UT-CP-002: Pinned Artifacts Protected
// =============================================================================

/// Tests that pinned artifacts are protected from TTL eviction.
#[test]
fn test_pinned_artifact_protected_from_eviction() {
    let mut artifact = create_artifact("pin-001", EvidenceClass::Ephemeral, TEST_TIMESTAMP_NS);

    // Pin the artifact with no expiration
    artifact.pin(
        PinReason::defect_binding("DEF-001"),
        None, // indefinite
        TEST_TIMESTAMP_NS,
    );

    // Even after TTL expires, pinned artifact should not be evicted
    let long_after_ttl = TEST_TIMESTAMP_NS + (EPHEMERAL_TTL_SECS * 1_000_000_000 * 10);
    assert!(!artifact.is_expired(long_after_ttl));
    assert!(!artifact.should_evict(long_after_ttl));

    // Remaining TTL should be MAX for indefinitely pinned
    assert_eq!(artifact.remaining_ttl_secs(long_after_ttl), u64::MAX);
}

/// Tests that unpinning allows eviction.
#[test]
fn test_unpin_allows_eviction() {
    let mut artifact = create_artifact("pin-002", EvidenceClass::Ephemeral, TEST_TIMESTAMP_NS);

    // Pin the artifact
    artifact.pin(
        PinReason::incident_investigation("INC-001", "Investigation"),
        None,
        TEST_TIMESTAMP_NS,
    );

    // After TTL, still not evictable (pinned)
    let after_ttl = TEST_TIMESTAMP_NS + (EPHEMERAL_TTL_SECS * 1_000_000_000);
    assert!(!artifact.should_evict(after_ttl));

    // Unpin
    artifact.unpin();
    assert!(!artifact.is_pinned());

    // Now should be evictable
    assert!(artifact.should_evict(after_ttl));
}

/// Tests different pin reasons.
#[test]
fn test_various_pin_reasons() {
    let mut artifact = create_artifact("pin-003", EvidenceClass::Standard, TEST_TIMESTAMP_NS);

    // Defect binding
    artifact.pin(
        PinReason::defect_binding("DEF-123"),
        None,
        TEST_TIMESTAMP_NS,
    );
    assert_eq!(
        artifact.pin_state().reason().unwrap().reason_type(),
        "defect_binding"
    );
    artifact.unpin();

    // Incident investigation
    artifact.pin(
        PinReason::incident_investigation("INC-456", "Security review"),
        None,
        TEST_TIMESTAMP_NS,
    );
    assert_eq!(
        artifact.pin_state().reason().unwrap().reason_type(),
        "incident_investigation"
    );
    artifact.unpin();

    // Compliance hold
    artifact.pin(
        PinReason::compliance_hold("SOC2-001", "SOC2"),
        None,
        TEST_TIMESTAMP_NS,
    );
    assert_eq!(
        artifact.pin_state().reason().unwrap().reason_type(),
        "compliance_hold"
    );
    artifact.unpin();

    // Manual hold
    artifact.pin(
        PinReason::manual_hold("admin@example.com", "Audit retention"),
        None,
        TEST_TIMESTAMP_NS,
    );
    assert_eq!(
        artifact.pin_state().reason().unwrap().reason_type(),
        "manual_hold"
    );
    artifact.unpin();

    // Quarantine evidence
    artifact.pin(
        PinReason::quarantine_evidence(&test_episode_id("quarantine")),
        None,
        TEST_TIMESTAMP_NS,
    );
    assert_eq!(
        artifact.pin_state().reason().unwrap().reason_type(),
        "quarantine_evidence"
    );
}

// =============================================================================
// UT-CP-003: Compaction Produces Valid Receipts
// =============================================================================

/// Tests that compaction job can be built and executed.
#[test]
fn test_compaction_job_execution() {
    use apm2_daemon::evidence::compaction::ArtifactId;

    let artifacts = vec![
        ArtifactId::new([0xaa; 32], ArtifactKind::ToolEvent, TEST_TIMESTAMP_NS, 1024),
        ArtifactId::new(
            [0xbb; 32],
            ArtifactKind::ToolEvent,
            TEST_TIMESTAMP_NS + 1000,
            2048,
        ),
    ];

    let job = CompactionJob::builder()
        .episode_id(test_episode_id("job-001"))
        .strategy(CompactionStrategy::DigestOnly)
        .artifacts(artifacts)
        .expect("artifacts should be accepted")
        .build()
        .expect("job build should succeed");

    // Validate the job
    assert!(job.validate().is_ok());

    // Execute the job
    let summary_hash = compute_hash(b"summary content");
    let result = job
        .execute(TEST_TIMESTAMP_NS + 10_000_000_000, summary_hash)
        .expect("execution should succeed");

    // Verify result
    assert_eq!(result.summary_hash, summary_hash);
    assert_eq!(result.compacted_count, 2);
    assert_eq!(result.tombstones.len(), 2);
    assert!(result.has_compacted());
}

/// Tests compaction with time window strategy.
#[test]
fn test_compaction_time_window_strategy() {
    use apm2_daemon::evidence::compaction::ArtifactId;

    // Calculate a current time that is 2 hours after TEST_TIMESTAMP_NS
    let current_time = TEST_TIMESTAMP_NS + (2 * 3600 * 1_000_000_000);

    // Old artifact: created at TEST_TIMESTAMP_NS (2 hours ago, > 1 hour threshold)
    // Recent artifact: created 30 minutes ago (< 1 hour threshold)
    let recent_artifact_time = current_time - (30 * 60 * 1_000_000_000); // 30 min ago

    let artifacts = vec![
        ArtifactId::new([0xaa; 32], ArtifactKind::ToolEvent, TEST_TIMESTAMP_NS, 1024), // Old
        ArtifactId::new(
            [0xbb; 32],
            ArtifactKind::ToolEvent,
            recent_artifact_time,
            2048,
        ), // Recent
    ];

    let job = CompactionJob::builder()
        .episode_id(test_episode_id("window-001"))
        .strategy(CompactionStrategy::TimeWindow)
        .threshold_ns(MIN_COMPACTION_THRESHOLD_NS) // 1 hour threshold
        .artifacts(artifacts)
        .expect("artifacts should be accepted")
        .build()
        .expect("job build should succeed");

    let summary_hash = compute_hash(b"summary");
    let result = job.execute(current_time, summary_hash).expect("execution");

    // Only old artifact (2 hours old) should be compacted, recent (30 min) retained
    assert_eq!(result.compacted_count, 1);
    assert_eq!(result.retained_count, 1);
}

/// Tests compaction summary creation.
#[test]
fn test_compaction_summary_creation() {
    let summary = CompactionSummary::new(
        test_episode_id("summary-001"),
        vec![[0xaa; 32], [0xbb; 32], [0xcc; 32]],
        CompactionCounts::default(),
        4096,
        TEST_TIMESTAMP_NS,
        CompactionStrategy::DigestOnly,
    );

    assert_eq!(summary.total_artifacts(), 3);
    assert_eq!(summary.total_size_bytes, 4096);
    assert!(summary.compute_hash().is_ok());
}

// =============================================================================
// UT-CP-004: Tombstone References Correct
// =============================================================================

/// Tests that tombstones correctly reference original artifacts.
#[test]
fn test_tombstone_references_original() {
    let original_hash = compute_hash(b"original content");
    let summary_hash = compute_hash(b"summary content");

    let tombstone = Tombstone::new(
        original_hash,
        summary_hash,
        TEST_TIMESTAMP_NS,
        ArtifactKind::ToolEvent,
    );

    assert_eq!(tombstone.original_hash, original_hash);
    assert_eq!(tombstone.summary_hash, summary_hash);
    assert_eq!(tombstone.dropped_at, TEST_TIMESTAMP_NS);
    assert_eq!(tombstone.artifact_kind, ArtifactKind::ToolEvent);
}

/// Tests tombstone validation.
#[test]
fn test_tombstone_validation() {
    // Valid tombstone
    let valid = Tombstone::new(
        [0xaa; 32],
        [0xbb; 32],
        TEST_TIMESTAMP_NS,
        ArtifactKind::Generic,
    );
    assert!(valid.validate().is_ok());

    // Invalid: zero timestamp
    let invalid = Tombstone::new([0xaa; 32], [0xbb; 32], 0, ArtifactKind::Generic);
    assert!(invalid.validate().is_err());
}

/// Tests tombstone canonical bytes determinism.
#[test]
fn test_tombstone_canonical_bytes_determinism() {
    let t1 = Tombstone::new(
        [0xaa; 32],
        [0xbb; 32],
        TEST_TIMESTAMP_NS,
        ArtifactKind::ToolEvent,
    );
    let t2 = Tombstone::new(
        [0xaa; 32],
        [0xbb; 32],
        TEST_TIMESTAMP_NS,
        ArtifactKind::ToolEvent,
    );

    assert_eq!(
        t1.canonical_bytes(),
        t2.canonical_bytes(),
        "identical tombstones must have identical canonical bytes"
    );
    assert_eq!(
        t1.digest(),
        t2.digest(),
        "identical tombstones must have identical digests"
    );
}

/// Tests that different tombstones have different digests.
#[test]
fn test_tombstone_different_digests() {
    let t1 = Tombstone::new(
        [0xaa; 32],
        [0xbb; 32],
        TEST_TIMESTAMP_NS,
        ArtifactKind::ToolEvent,
    );
    let t2 = Tombstone::new(
        [0xcc; 32], // Different original hash
        [0xbb; 32],
        TEST_TIMESTAMP_NS,
        ArtifactKind::ToolEvent,
    );

    assert_ne!(t1.digest(), t2.digest());
}

/// Tests tombstone list canonical bytes are sorted.
#[test]
fn test_tombstone_list_sorted_canonical_bytes() {
    // Create lists with different insertion orders
    let mut list1 = TombstoneList::new();
    list1
        .push(Tombstone::new(
            [0xff; 32],
            [0xbb; 32],
            TEST_TIMESTAMP_NS,
            ArtifactKind::Generic,
        ))
        .unwrap();
    list1
        .push(Tombstone::new(
            [0x00; 32],
            [0xbb; 32],
            TEST_TIMESTAMP_NS,
            ArtifactKind::Generic,
        ))
        .unwrap();

    let mut list2 = TombstoneList::new();
    list2
        .push(Tombstone::new(
            [0x00; 32],
            [0xbb; 32],
            TEST_TIMESTAMP_NS,
            ArtifactKind::Generic,
        ))
        .unwrap();
    list2
        .push(Tombstone::new(
            [0xff; 32],
            [0xbb; 32],
            TEST_TIMESTAMP_NS,
            ArtifactKind::Generic,
        ))
        .unwrap();

    // Despite different insertion order, canonical bytes should match
    assert_eq!(
        list1.canonical_bytes(),
        list2.canonical_bytes(),
        "tombstone list should sort for determinism"
    );
}

// =============================================================================
// UT-CP-005: Pin Expiration Scenarios
// =============================================================================

/// Tests pin with expiration.
#[test]
fn test_pin_with_expiration() {
    let mut artifact = create_artifact("pin-exp-001", EvidenceClass::Ephemeral, TEST_TIMESTAMP_NS);

    // Pin expires after 2 hours (artifact TTL is 1 hour)
    let pin_expires = TEST_TIMESTAMP_NS + (2 * 3600 * 1_000_000_000);
    artifact.pin(
        PinReason::manual_hold("user", "temporary hold"),
        Some(pin_expires),
        TEST_TIMESTAMP_NS,
    );

    // Pin not expired before expiration
    let before_pin_exp = TEST_TIMESTAMP_NS + (3600 * 1_000_000_000); // 1 hour
    assert!(!artifact.is_pin_expired(before_pin_exp));
    assert!(!artifact.should_evict(before_pin_exp));

    // Pin expired at expiration time
    assert!(artifact.is_pin_expired(pin_expires));

    // After pin expires AND TTL expires, should evict
    // TTL expired at 1 hour, pin at 2 hours
    // At 2 hours, both are expired, so should evict
    assert!(artifact.should_evict(pin_expires));
}

/// Tests pin expiration before TTL.
#[test]
fn test_pin_expires_before_ttl() {
    let mut artifact = create_artifact("pin-exp-002", EvidenceClass::Standard, TEST_TIMESTAMP_NS);

    // Pin expires in 1 hour, TTL is 7 days
    let one_hour_ns = 3600 * 1_000_000_000;
    let pin_expires = TEST_TIMESTAMP_NS + one_hour_ns;

    artifact.pin(
        PinReason::manual_hold("user", "short hold"),
        Some(pin_expires),
        TEST_TIMESTAMP_NS,
    );

    // After pin expires but before TTL
    let after_pin_before_ttl = TEST_TIMESTAMP_NS + (2 * 3600 * 1_000_000_000);
    assert!(artifact.is_pin_expired(after_pin_before_ttl));
    // Should NOT evict because TTL hasn't expired
    assert!(!artifact.should_evict(after_pin_before_ttl));

    // After both pin and TTL expire
    let after_ttl = TEST_TIMESTAMP_NS + (STANDARD_TTL_SECS * 1_000_000_000);
    assert!(artifact.should_evict(after_ttl));
}

/// Tests indefinite pin never expires.
#[test]
fn test_indefinite_pin_never_expires() {
    let mut artifact = create_artifact("pin-exp-003", EvidenceClass::Ephemeral, TEST_TIMESTAMP_NS);

    // Pin with no expiration
    artifact.pin(
        PinReason::compliance_hold("AUDIT-001", "Indefinite retention"),
        None, // No expiration
        TEST_TIMESTAMP_NS,
    );

    // Even at u64::MAX - 1 (close to max), should not be expired
    assert!(!artifact.is_pin_expired(u64::MAX - 1));
    assert!(!artifact.should_evict(u64::MAX - 1));
}

// =============================================================================
// UT-CP-006: TTL Enforcer Operations
// =============================================================================

/// Tests TTL enforcer can be created and configured.
#[test]
fn test_ttl_enforcer_creation() {
    let config = TtlEnforcerConfig::default();
    let enforcer = TtlEnforcer::new(config);

    assert!(enforcer.is_empty());
    assert_eq!(enforcer.artifact_count(), 0);
}

/// Tests TTL enforcer artifact management.
#[test]
fn test_ttl_enforcer_artifact_management() {
    let config = TtlEnforcerConfig::default();
    let mut enforcer = TtlEnforcer::new(config);

    // Add an artifact
    let artifact = EvidenceArtifact::try_new(
        "art-001",
        [0xaa; 32],
        EvidenceClass::Ephemeral,
        "ep-test",
        TEST_TIMESTAMP_NS,
    )
    .unwrap();

    enforcer.add_artifact(artifact).unwrap();
    assert_eq!(enforcer.artifact_count(), 1);

    // Retrieve the artifact
    let retrieved = enforcer.get_artifact("art-001");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().artifact_id().as_str(), "art-001");

    // Remove the artifact
    let removed = enforcer.remove_artifact("art-001");
    assert!(removed.is_some());
    assert!(enforcer.is_empty());
}

/// Tests TTL enforcer eviction of expired artifacts.
#[test]
fn test_ttl_enforcer_eviction() {
    let config = TtlEnforcerConfig::default();
    let mut enforcer = TtlEnforcer::new(config);

    // Add ephemeral artifact
    let artifact = EvidenceArtifact::try_new(
        "art-exp-001",
        [0xaa; 32],
        EvidenceClass::Ephemeral,
        "ep-test",
        TEST_TIMESTAMP_NS,
    )
    .unwrap();

    enforcer.add_artifact(artifact).unwrap();

    // Before TTL - no eviction
    let (events, stats) = enforcer.enforce_ttl(TEST_TIMESTAMP_NS);
    assert_eq!(events.len(), 0);
    assert_eq!(stats.artifacts_evicted, 0);
    assert_eq!(stats.active_artifacts, 1);

    // After TTL - eviction
    let after_ttl = TEST_TIMESTAMP_NS + (EPHEMERAL_TTL_SECS * 1_000_000_000) + 1;
    let (events, stats) = enforcer.enforce_ttl(after_ttl);

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].artifact_id, "art-exp-001");
    assert_eq!(stats.artifacts_evicted, 1);
    assert!(enforcer.is_empty());
}

/// Tests TTL enforcer respects pinning.
#[test]
fn test_ttl_enforcer_respects_pinning() {
    let config = TtlEnforcerConfig::default();
    let mut enforcer = TtlEnforcer::new(config);

    // Add and pin artifact
    let mut artifact = EvidenceArtifact::try_new(
        "art-pin-001",
        [0xaa; 32],
        EvidenceClass::Ephemeral,
        "ep-test",
        TEST_TIMESTAMP_NS,
    )
    .unwrap();

    artifact.pin(
        PinReason::defect_binding("DEF-001"),
        None,
        TEST_TIMESTAMP_NS,
    );
    enforcer.add_artifact(artifact).unwrap();

    // After TTL - should not be evicted because pinned
    let after_ttl = TEST_TIMESTAMP_NS + (EPHEMERAL_TTL_SECS * 1_000_000_000) + 1;
    let (events, stats) = enforcer.enforce_ttl(after_ttl);

    assert_eq!(events.len(), 0);
    assert_eq!(stats.pinned_skipped, 1);
    assert_eq!(enforcer.artifact_count(), 1);
}

// =============================================================================
// UT-CP-007: Artifact Kind Classification
// =============================================================================

/// Tests all artifact kinds have correct values.
#[test]
fn test_artifact_kind_values() {
    assert_eq!(ArtifactKind::PtyTranscript.value(), 1);
    assert_eq!(ArtifactKind::ToolEvent.value(), 2);
    assert_eq!(ArtifactKind::TelemetryFrame.value(), 3);
    assert_eq!(ArtifactKind::EvidenceBundle.value(), 4);
    assert_eq!(ArtifactKind::Generic.value(), 5);
}

/// Tests artifact kind roundtrip through value.
#[test]
fn test_artifact_kind_value_roundtrip() {
    for kind in [
        ArtifactKind::PtyTranscript,
        ArtifactKind::ToolEvent,
        ArtifactKind::TelemetryFrame,
        ArtifactKind::EvidenceBundle,
        ArtifactKind::Generic,
    ] {
        let value = kind.value();
        let restored = ArtifactKind::from_value(value);
        assert_eq!(restored, Some(kind), "roundtrip failed for {kind:?}");
    }
}

/// Tests artifact kind display.
#[test]
fn test_artifact_kind_display() {
    assert_eq!(ArtifactKind::PtyTranscript.to_string(), "pty_transcript");
    assert_eq!(ArtifactKind::ToolEvent.to_string(), "tool_event");
    assert_eq!(ArtifactKind::TelemetryFrame.to_string(), "telemetry_frame");
    assert_eq!(ArtifactKind::EvidenceBundle.to_string(), "evidence_bundle");
    assert_eq!(ArtifactKind::Generic.to_string(), "generic");
}

// =============================================================================
// UT-CP-008: Serialization Integrity
// =============================================================================

/// Tests tombstone serialization roundtrip.
#[test]
fn test_tombstone_serialization_roundtrip() {
    let tombstone = Tombstone::new(
        [0xaa; 32],
        [0xbb; 32],
        TEST_TIMESTAMP_NS,
        ArtifactKind::ToolEvent,
    );

    let json = serde_json::to_string(&tombstone).expect("serialization should succeed");
    let restored: Tombstone = serde_json::from_str(&json).expect("deserialization should succeed");

    assert_eq!(tombstone, restored);
}

/// Tests tombstone list serialization roundtrip.
#[test]
fn test_tombstone_list_serialization_roundtrip() {
    let mut list = TombstoneList::new();
    list.push(Tombstone::new(
        [0xaa; 32],
        [0xbb; 32],
        TEST_TIMESTAMP_NS,
        ArtifactKind::ToolEvent,
    ))
    .unwrap();
    list.push(Tombstone::new(
        [0xcc; 32],
        [0xdd; 32],
        TEST_TIMESTAMP_NS + 1000,
        ArtifactKind::TelemetryFrame,
    ))
    .unwrap();

    let json = serde_json::to_string(&list).expect("serialization should succeed");
    let restored: TombstoneList =
        serde_json::from_str(&json).expect("deserialization should succeed");

    assert_eq!(list, restored);
}

/// Tests artifact serialization roundtrip.
#[test]
fn test_artifact_serialization_roundtrip() {
    let mut artifact = create_artifact("serde-001", EvidenceClass::Standard, TEST_TIMESTAMP_NS);
    artifact.pin(
        PinReason::defect_binding("DEF-001"),
        Some(TEST_TIMESTAMP_NS + 3_600_000_000_000),
        TEST_TIMESTAMP_NS,
    );

    let json = serde_json::to_string(&artifact).expect("serialization should succeed");
    let restored: EvidenceArtifact =
        serde_json::from_str(&json).expect("deserialization should succeed");

    assert_eq!(artifact, restored);
    assert!(restored.is_pinned());
}

/// SECURITY: Tests that unknown fields are rejected.
#[test]
fn test_tombstone_rejects_unknown_fields() {
    let json = r#"{
        "original_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "summary_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "dropped_at": 1000000000,
        "artifact_kind": "generic",
        "malicious_field": "attack"
    }"#;

    let result: Result<Tombstone, _> = serde_json::from_str(json);
    assert!(result.is_err(), "should reject unknown fields");
}

// =============================================================================
// UT-CP-009: Compaction Strategy Tests
// =============================================================================

/// Tests compaction strategy default.
#[test]
fn test_compaction_strategy_default() {
    assert_eq!(
        CompactionStrategy::default(),
        CompactionStrategy::DigestOnly
    );
}

/// Tests compaction strategy roundtrip through value.
#[test]
fn test_compaction_strategy_value_roundtrip() {
    for strategy in [
        CompactionStrategy::CountSummary,
        CompactionStrategy::DigestOnly,
        CompactionStrategy::TimeWindow,
    ] {
        let value = strategy.value();
        let restored = CompactionStrategy::from_value(value);
        assert_eq!(
            restored,
            Some(strategy),
            "roundtrip failed for {strategy:?}"
        );
    }
}

/// Tests compaction strategy display.
#[test]
fn test_compaction_strategy_display() {
    assert_eq!(
        CompactionStrategy::CountSummary.to_string(),
        "count_summary"
    );
    assert_eq!(CompactionStrategy::DigestOnly.to_string(), "digest_only");
    assert_eq!(CompactionStrategy::TimeWindow.to_string(), "time_window");
}
