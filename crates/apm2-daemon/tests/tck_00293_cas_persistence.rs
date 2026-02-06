//! TCK-00293: CAS persistence across daemon restarts
//!
//! This test module verifies that the durable CAS correctly persists
//! evidence artifacts across daemon restarts.
//!
//! # Acceptance Criteria
//!
//! 1. Durable CAS persists artifacts across daemon restarts
//! 2. Stub/in-memory CAS is not used in production paths
//! 3. CAS size limits and hash verification are enforced
//!
//! # Security Properties
//!
//! Per RFC-0018 and REQ-HEF-0009:
//! - Evidence artifacts must be durable and content-addressed
//! - Transient CAS is not acceptable for FAC v0

use std::sync::Arc;

use apm2_daemon::cas::{DurableCas, DurableCasConfig, DurableCasError};
use apm2_daemon::episode::executor::ContentAddressedStore;
use tempfile::TempDir;

// =============================================================================
// TCK-00293: AC1 - Durable CAS persists artifacts across daemon restarts
// =============================================================================

/// Verify that content stored in the CAS survives a simulated daemon restart.
///
/// Per TCK-00293 AC1: Durable CAS persists artifacts across daemon restarts
/// Verification: `cargo test -p apm2-daemon cas_persistence_restart`
#[test]
fn cas_persistence_restart_basic() {
    let temp_dir = TempDir::new().unwrap();
    let content = b"test evidence artifact content";
    let hash;

    // First "daemon instance": store content
    {
        let config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = DurableCas::new(config).unwrap();
        let result = cas.store(content).unwrap();
        hash = result.hash;
        assert!(result.is_new, "First store should be new");
    }

    // Simulate daemon restart: create new CAS instance
    {
        let config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = DurableCas::new(config).unwrap();

        // Content should still exist
        assert!(cas.exists(&hash), "Content should exist after restart");

        // Content should be retrievable
        let retrieved = cas.retrieve(&hash).unwrap();
        assert_eq!(retrieved, content, "Retrieved content should match");

        // Store should detect duplicate
        let result = cas.store(content).unwrap();
        assert!(!result.is_new, "Duplicate store should not be new");
    }
}

/// Verify multiple artifacts persist across restart.
#[test]
fn cas_persistence_restart_multiple_artifacts() {
    let temp_dir = TempDir::new().unwrap();
    let artifacts = vec![
        b"artifact 1: test results".to_vec(),
        b"artifact 2: code review".to_vec(),
        b"artifact 3: change set bundle".to_vec(),
    ];
    let mut hashes = Vec::new();

    // First instance: store all artifacts
    {
        let config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = DurableCas::new(config).unwrap();

        for artifact in &artifacts {
            let result = cas.store(artifact).unwrap();
            hashes.push(result.hash);
        }
    }

    // Second instance: verify all artifacts
    {
        let config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = DurableCas::new(config).unwrap();

        for (i, (artifact, hash)) in artifacts.iter().zip(&hashes).enumerate() {
            assert!(cas.exists(hash), "Artifact {i} should exist after restart");
            let retrieved = cas.retrieve(hash).unwrap();
            assert_eq!(&retrieved, artifact, "Artifact {i} content should match");
        }
    }
}

/// Verify total size is preserved across restart.
#[test]
fn cas_persistence_restart_total_size() {
    let temp_dir = TempDir::new().unwrap();
    let artifact1 = b"12345"; // 5 bytes
    let artifact2 = b"1234567890"; // 10 bytes
    let expected_size = 15;

    // First instance: store artifacts
    {
        let config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = DurableCas::new(config).unwrap();
        cas.store(artifact1).unwrap();
        cas.store(artifact2).unwrap();
        assert_eq!(
            cas.total_size(),
            expected_size,
            "Total size should be sum of artifacts"
        );
    }

    // Second instance: verify total size persisted
    {
        let config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = DurableCas::new(config).unwrap();
        assert_eq!(
            cas.total_size(),
            expected_size,
            "Total size should persist across restart"
        );
    }
}

// =============================================================================
// TCK-00293: AC3 - CAS size limits and hash verification are enforced
// =============================================================================

/// Verify per-artifact size limit is enforced.
#[test]
fn cas_size_limit_per_artifact() {
    let temp_dir = TempDir::new().unwrap();
    let config = DurableCasConfig::new(temp_dir.path().join("cas")).with_max_artifact_size(100);
    let cas = DurableCas::new(config).unwrap();

    // Content within limit should succeed
    let small = vec![0u8; 100];
    let result = cas.store(&small);
    assert!(result.is_ok(), "Content at limit should succeed");

    // Content exceeding limit should fail
    let large = vec![0u8; 101];
    let result = cas.store(&large);
    assert!(
        matches!(result, Err(DurableCasError::ContentTooLarge { .. })),
        "Content exceeding limit should fail"
    );
}

/// Verify total storage limit is enforced.
#[test]
fn cas_size_limit_total_storage() {
    let temp_dir = TempDir::new().unwrap();
    let config = DurableCasConfig::new(temp_dir.path().join("cas"))
        .with_max_artifact_size(100)
        .with_max_total_size(200);
    let cas = DurableCas::new(config).unwrap();

    // First artifact: 80 bytes
    cas.store(&[0u8; 80]).unwrap();

    // Second artifact: 80 bytes (total 160)
    cas.store(&[1u8; 80]).unwrap();

    // Third artifact would exceed total limit
    let result = cas.store(&[2u8; 80]);
    assert!(
        matches!(result, Err(DurableCasError::StorageFull { .. })),
        "Storage should be full"
    );
}

/// Verify hash verification on retrieve.
#[test]
fn cas_hash_verification_on_retrieve() {
    let temp_dir = TempDir::new().unwrap();
    let config = DurableCasConfig::new(temp_dir.path().join("cas"));
    let cas = DurableCas::new(config).unwrap();

    let content = b"test content for hash verification";
    let result = cas.store(content).unwrap();

    // Normal retrieval should succeed and verify hash
    let retrieved = cas.retrieve(&result.hash).unwrap();
    assert_eq!(retrieved, content);

    // Verify method should work correctly
    assert!(cas.verify(content, &result.hash).is_ok());

    // Verify with wrong content should fail
    let wrong_content = b"wrong content";
    assert!(
        matches!(
            cas.verify(wrong_content, &result.hash),
            Err(DurableCasError::HashMismatch { .. })
        ),
        "Verification should fail for wrong content"
    );
}

/// Verify empty content is rejected.
#[test]
fn cas_reject_empty_content() {
    let temp_dir = TempDir::new().unwrap();
    let config = DurableCasConfig::new(temp_dir.path().join("cas"));
    let cas = DurableCas::new(config).unwrap();

    let result = cas.store(b"");
    assert!(
        matches!(result, Err(DurableCasError::EmptyContent)),
        "Empty content should be rejected"
    );
}

/// Verify content deduplication works correctly.
#[test]
fn cas_deduplication() {
    let temp_dir = TempDir::new().unwrap();
    let config = DurableCasConfig::new(temp_dir.path().join("cas"));
    let cas = DurableCas::new(config).unwrap();

    let content = b"deduplicated content";

    let result1 = cas.store(content).unwrap();
    assert!(result1.is_new, "First store should be new");

    let result2 = cas.store(content).unwrap();
    assert!(!result2.is_new, "Second store should not be new");
    assert_eq!(result1.hash, result2.hash, "Hashes should match");

    // Total size should only count once
    assert_eq!(cas.total_size(), content.len());
}

// =============================================================================
// TCK-00293: Integration with ContentAddressedStore trait
// =============================================================================

/// Verify `DurableCas` implements `ContentAddressedStore` trait correctly.
#[test]
fn cas_trait_implementation() {
    let temp_dir = TempDir::new().unwrap();
    let config = DurableCasConfig::new(temp_dir.path().join("cas"));
    let cas = Arc::new(DurableCas::new(config).unwrap());

    // Use via trait object (as would be done in ToolBroker)
    let cas_trait: Arc<dyn ContentAddressedStore> = cas;

    let content = b"test content via trait";
    let hash = cas_trait.store(content);

    // Should be retrievable via trait
    let retrieved = cas_trait.retrieve(&hash);
    assert!(
        retrieved.is_some(),
        "Content should be retrievable via trait"
    );
    assert_eq!(retrieved.unwrap(), content);

    // Contains should work
    assert!(cas_trait.contains(&hash), "Contains should return true");

    let fake_hash = [0u8; 32];
    assert!(
        !cas_trait.contains(&fake_hash),
        "Contains should return false for missing content"
    );
}

/// Verify deterministic hashing across CAS instances.
#[test]
fn cas_deterministic_hash() {
    let temp_dir1 = TempDir::new().unwrap();
    let temp_dir2 = TempDir::new().unwrap();

    let config1 = DurableCasConfig::new(temp_dir1.path().join("cas"));
    let config2 = DurableCasConfig::new(temp_dir2.path().join("cas"));

    let cas1 = DurableCas::new(config1).unwrap();
    let cas2 = DurableCas::new(config2).unwrap();

    let content = b"deterministic content";

    let result1 = cas1.store(content).unwrap();
    let result2 = cas2.store(content).unwrap();

    assert_eq!(
        result1.hash, result2.hash,
        "Hashes should be deterministic across CAS instances"
    );
}

// =============================================================================
// TCK-00293: Crash recovery scenarios
// =============================================================================

/// Verify CAS can recover from metadata file corruption.
#[test]
fn cas_recovery_from_corrupted_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let content = b"content before corruption";
    let hash;
    let original_size;

    // First instance: store content
    {
        let config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = DurableCas::new(config).unwrap();
        let result = cas.store(content).unwrap();
        hash = result.hash;
        original_size = cas.total_size();
    }

    // Corrupt the metadata file
    let metadata_file = temp_dir
        .path()
        .join("cas")
        .join("metadata")
        .join("total_size");
    std::fs::write(&metadata_file, "invalid").unwrap();

    // New instance should recover by recalculating
    {
        let config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = DurableCas::new(config).unwrap();

        // Content should still be retrievable
        let retrieved = cas.retrieve(&hash).unwrap();
        assert_eq!(retrieved, content);

        // Total size should be recalculated
        assert_eq!(cas.total_size(), original_size);
    }
}

/// Verify CAS handles missing objects directory gracefully.
#[test]
fn cas_creation_with_fresh_directory() {
    let temp_dir = TempDir::new().unwrap();
    let cas_path = temp_dir.path().join("new_cas");

    // CAS should create necessary directories
    let config = DurableCasConfig::new(&cas_path);
    let cas = DurableCas::new(config).unwrap();

    // Should be able to store and retrieve
    let content = b"fresh CAS content";
    let result = cas.store(content).unwrap();
    let retrieved = cas.retrieve(&result.hash).unwrap();
    assert_eq!(retrieved, content);
}
