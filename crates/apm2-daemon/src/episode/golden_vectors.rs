//! Golden test vectors for episode envelope hash stability verification.
//!
//! This module contains golden vectors that verify the deterministic encoding
//! of episode envelope types. Each vector consists of:
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
//! - **Digest stability**: Verify that envelope digests bound into receipts
//!   remain stable across serialization cycles
//! - **Cross-platform consistency**: Ensure wire format is consistent
//!   regardless of compilation target
//!
//! # Contract References
//!
//! - AD-EPISODE-001: Immutable episode envelope
//! - AD-VERIFY-001: Deterministic Protobuf serialization (`canonical_bytes`)
//! - REQ-EPISODE-001: Episode envelope requirements
//!
//! # Updating Vectors
//!
//! When message definitions change:
//! 1. Update the message construction in the vector
//! 2. Run tests to get new expected values
//! 3. Verify changes are intentional (breaking change = new protocol version)
//! 4. Update expected bytes and hashes

use super::budget::EpisodeBudget;
use super::envelope::{ContextRefs, DeterminismClass, EpisodeEnvelope, RiskTier, StopConditions};
use super::snapshot::PinnedSnapshot;

/// A golden test vector for episode types.
pub struct GoldenVector {
    /// Human-readable name for the vector.
    pub name: &'static str,
    /// Contract reference (e.g., "AD-EPISODE-001").
    pub contract: &'static str,
    /// Expected BLAKE3 hash of the canonical bytes (hex-encoded).
    pub expected_hash: &'static str,
    /// Expected canonical bytes (hex-encoded).
    pub expected_bytes: &'static str,
}

// ============================================================================
// EpisodeBudget vectors
// ============================================================================

/// Golden vector for default budget.
pub const BUDGET_DEFAULT_VECTOR: GoldenVector = GoldenVector {
    name: "budget_default",
    contract: "AD-EPISODE-001",
    expected_hash: "58247a9c29986ef0ef9bf290c9222784c86a1988d2daf67c3fd288d70ac21b9e",
    expected_bytes: "08c0843d10904e1880dddb0120c0cf242880808080283080808032",
};

/// Golden vector for unlimited budget.
///
/// Per AD-VERIFY-001, all fields are explicitly serialized even when they
/// contain default values (0). This ensures deterministic encoding regardless
/// of Protobuf implementation details.
pub const BUDGET_UNLIMITED_VECTOR: GoldenVector = GoldenVector {
    name: "budget_unlimited",
    contract: "AD-EPISODE-001",
    expected_hash: "99286982d4aad771d25451896f87d7e304930adfc03e576747c46111ff9a8fc4",
    expected_bytes: "080010001800200028003000",
};

/// Golden vector for minimal budget.
///
/// Per AD-VERIFY-001, all fields are explicitly serialized including
/// `bytes_io=0` and `evidence_bytes=0`.
pub const BUDGET_MINIMAL_VECTOR: GoldenVector = GoldenVector {
    name: "budget_minimal",
    contract: "AD-EPISODE-001",
    expected_hash: "06b2a3eb4a3cfdb24a5d36e1323072b4789c35dbbb2e3f5c80dc3d7553474d92",
    expected_bytes: "08a08d06103218cc0820a08d0628003000",
};

// ============================================================================
// PinnedSnapshot vectors
// ============================================================================

/// Golden vector for empty snapshot.
///
/// Per AD-VERIFY-001, empty hashes are explicitly serialized (using optional
/// bytes fields) to ensure deterministic encoding.
pub const SNAPSHOT_EMPTY_VECTOR: GoldenVector = GoldenVector {
    name: "snapshot_empty",
    contract: "AD-EPISODE-001",
    expected_hash: "148b0b75ef1104cb4bd1e852f8f908de471997f2ac4286a00a65760a227d592f",
    expected_bytes: "0a0012001a0022002a00",
};

/// Golden vector for snapshot with repo hash only.
///
/// Per AD-VERIFY-001, empty hashes are explicitly serialized (using optional
/// bytes fields) to ensure deterministic encoding.
pub const SNAPSHOT_REPO_ONLY_VECTOR: GoldenVector = GoldenVector {
    name: "snapshot_repo_only",
    contract: "AD-EPISODE-001",
    expected_hash: "9acca522bf85c06695c5b009b768a1597f6a915ba72eaddfe3a32621167af017",
    expected_bytes: "0a20abababababababababababababababababababababababababababababababab12001a0022002a00",
};

/// Golden vector for full snapshot.
pub const SNAPSHOT_FULL_VECTOR: GoldenVector = GoldenVector {
    name: "snapshot_full",
    contract: "AD-EPISODE-001",
    expected_hash: "51ed39c2a177e10a236530602489f0f9024852d8de74d5d31e15f2fc5b2ff2f3",
    expected_bytes: "0a201111111111111111111111111111111111111111111111111111111111111111122022222222222222222222222222222222222222222222222222222222222222221a203333333333333333333333333333333333333333333333333333333333333333222044444444444444444444444444444444444444444444444444444444444444442a205555555555555555555555555555555555555555555555555555555555555555",
};

// ============================================================================
// StopConditions vectors
// ============================================================================

/// Golden vector for stop conditions with max episodes only.
///
/// Per AD-VERIFY-001, all fields are explicitly serialized including
/// empty predicates.
pub const STOP_CONDITIONS_MAX_EPISODES_VECTOR: GoldenVector = GoldenVector {
    name: "stop_conditions_max_episodes",
    contract: "AD-EPISODE-001",
    expected_hash: "8dff9a7c067be7265cc861dbf1cbadd5234c3850fcb9f33730eb5f53800f37b0",
    expected_bytes: "086412001a002200",
};

/// Golden vector for stop conditions with predicates.
pub const STOP_CONDITIONS_WITH_PREDICATES_VECTOR: GoldenVector = GoldenVector {
    name: "stop_conditions_with_predicates",
    contract: "AD-EPISODE-001",
    expected_hash: "93d917456e8bd91405a6872a63676bf2ee0964a133b0cf1474f93fd86f2eb235",
    expected_bytes: "08641208676f616c5f6d65741a096661696c5f636f6e642203657363",
};

// ============================================================================
// EpisodeEnvelope vectors
// ============================================================================

/// Golden vector for minimal envelope (required fields only).
///
/// Per AD-EPISODE-001, minimal envelopes still include budget,
/// `stop_conditions`, and `pinned_snapshot`. Per AD-VERIFY-001, all fields are
/// explicitly serialized including empty snapshot hashes.
pub const ENVELOPE_MINIMAL_VECTOR: GoldenVector = GoldenVector {
    name: "envelope_minimal",
    contract: "AD-EPISODE-001",
    expected_hash: "a8af2457d3a50cd3bf38fbfbce0bac15f0d6e6ecf28b80b41a55a0f43f5b334b",
    expected_bytes: "0a0665702d30303112096167656e742d30303722096c656173652d3132332a0c0800100018002000280030003208080012001a0022003a0a0a0012001a0022002a0042200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2048005000",
};

/// Golden vector for envelope with all optional fields.
///
/// Per AD-VERIFY-001, all fields are explicitly serialized including
/// empty snapshot hashes.
pub const ENVELOPE_FULL_VECTOR: GoldenVector = GoldenVector {
    name: "envelope_full",
    contract: "AD-EPISODE-001",
    expected_hash: "5f1b0ec9a9b717cef327ef8afb2dea77e27956fdb4e7f47b323e63f404189896",
    expected_bytes: "0a0665702d30303112096167656e742d3030371a08776f726b2d34353622096c656173652d3132332a1108a08d06103218cc0820c0cf24280030003208086412001a0022003a2a0a20010203040506070801020304050607080102030405060708010203040506070812001a0022002a004220abababababababababababababababababababababababababababababababab480250025a300a20efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef1205646370313112056463703232",
};

/// Golden vector for envelope with sorted context refs.
///
/// Per AD-VERIFY-001, all fields are explicitly serialized and DCP refs are
/// sorted. Empty snapshot hashes are explicitly serialized.
pub const ENVELOPE_SORTED_DCP_REFS_VECTOR: GoldenVector = GoldenVector {
    name: "envelope_sorted_dcp_refs",
    contract: "AD-VERIFY-001",
    expected_hash: "383366a5a7ed9f05ede369b655734d1502425ee5f9658af3712d595472cd65fd",
    expected_bytes: "0a0265701206616374696f6e22056c656173652a0c0800100018002000280030003208080012001a0022003a0a0a0012001a0022002a0042200102030405060708010203040506070801020304050607080102030405060708480050005a0c12016112016212016312017a",
};

// ============================================================================
// Helper functions
// ============================================================================

/// Constructs the default budget for golden vector.
#[must_use]
pub fn construct_budget_default() -> EpisodeBudget {
    EpisodeBudget::default()
}

/// Constructs the unlimited budget for golden vector.
#[must_use]
pub const fn construct_budget_unlimited() -> EpisodeBudget {
    EpisodeBudget::unlimited()
}

/// Constructs a minimal budget for golden vector.
#[must_use]
pub const fn construct_budget_minimal() -> EpisodeBudget {
    EpisodeBudget::builder()
        .tokens(100_000)
        .tool_calls(50)
        .wall_ms(1100)
        .cpu_ms(100_000)
        .bytes_io(0)
        .evidence_bytes(0)
        .build()
}

/// Constructs an empty snapshot for golden vector.
#[must_use]
pub const fn construct_snapshot_empty() -> PinnedSnapshot {
    PinnedSnapshot::empty()
}

/// Constructs a snapshot with repo hash only for golden vector.
#[must_use]
pub fn construct_snapshot_repo_only() -> PinnedSnapshot {
    PinnedSnapshot::builder().repo_hash([0xab; 32]).build()
}

/// Constructs a full snapshot for golden vector.
#[must_use]
pub fn construct_snapshot_full() -> PinnedSnapshot {
    PinnedSnapshot::builder()
        .repo_hash([0x11; 32])
        .lockfile_hash([0x22; 32])
        .policy_hash([0x33; 32])
        .toolchain_hash([0x44; 32])
        .model_profile_hash([0x55; 32])
        .build()
}

/// Constructs stop conditions with max episodes for golden vector.
#[must_use]
pub const fn construct_stop_conditions_max_episodes() -> StopConditions {
    StopConditions::max_episodes(100)
}

/// Constructs stop conditions with predicates for golden vector.
#[must_use]
pub fn construct_stop_conditions_with_predicates() -> StopConditions {
    StopConditions {
        max_episodes: 100,
        goal_predicate: "goal_met".to_string(),
        failure_predicate: "fail_cond".to_string(),
        escalation_predicate: "esc".to_string(),
    }
}

/// Constructs a minimal envelope for golden vector.
///
/// Per AD-EPISODE-001, minimal envelopes still require budget,
/// `stop_conditions`, and `pinned_snapshot` fields.
#[must_use]
pub fn construct_envelope_minimal() -> EpisodeEnvelope {
    EpisodeEnvelope::builder()
        .episode_id("ep-001")
        .actor_id("agent-007")
        .lease_id("lease-123")
        .capability_manifest_hash([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])
        .budget(EpisodeBudget::unlimited())
        .stop_conditions(StopConditions::max_episodes(0))
        .pinned_snapshot(PinnedSnapshot::empty())
        .build()
        .expect("valid envelope")
}

/// Constructs a full envelope for golden vector.
#[must_use]
pub fn construct_envelope_full() -> EpisodeEnvelope {
    EpisodeEnvelope::builder()
        .episode_id("ep-001")
        .actor_id("agent-007")
        .work_id("work-456")
        .lease_id("lease-123")
        .budget(
            EpisodeBudget::builder()
                .tokens(100_000)
                .tool_calls(50)
                .wall_ms(1100)
                .bytes_io(0)
                .evidence_bytes(0)
                .build(),
        )
        .stop_conditions(StopConditions::max_episodes(100))
        .pinned_snapshot(
            PinnedSnapshot::builder()
                .repo_hash([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05,
                    0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02,
                    0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                ])
                .build(),
        )
        .capability_manifest_hash([0xab; 32])
        .risk_tier(RiskTier::Tier2)
        .determinism_class(DeterminismClass::FullyDeterministic)
        .context_refs(ContextRefs {
            context_pack_hash: vec![0xef; 32],
            dcp_refs: vec!["dcp11".to_string(), "dcp22".to_string()],
        })
        .build()
        .expect("valid envelope")
}

/// Constructs an envelope with unsorted DCP refs for golden vector.
///
/// This tests that `canonical_bytes` sorts DCP refs.
#[must_use]
pub fn construct_envelope_sorted_dcp_refs() -> EpisodeEnvelope {
    EpisodeEnvelope::builder()
        .episode_id("ep")
        .actor_id("action")
        .lease_id("lease")
        .capability_manifest_hash([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ])
        .budget(EpisodeBudget::unlimited())
        .stop_conditions(StopConditions::max_episodes(0))
        .pinned_snapshot(PinnedSnapshot::empty())
        .context_refs(ContextRefs {
            context_pack_hash: vec![],
            // Intentionally unsorted - canonical_bytes should sort these
            dcp_refs: vec![
                "z".to_string(),
                "a".to_string(),
                "c".to_string(),
                "b".to_string(),
            ],
        })
        .build()
        .expect("valid envelope")
}

/// Trait for types that support canonical bytes encoding.
#[cfg(test)]
trait CanonicalEncode {
    fn canonical_bytes(&self) -> Vec<u8>;
}

#[cfg(test)]
impl CanonicalEncode for EpisodeBudget {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

#[cfg(test)]
impl CanonicalEncode for PinnedSnapshot {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

#[cfg(test)]
impl CanonicalEncode for StopConditions {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

#[cfg(test)]
impl CanonicalEncode for EpisodeEnvelope {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify encoding matches expected bytes.
    fn verify_encoding<T: CanonicalEncode>(value: &T, vector: &GoldenVector) {
        let bytes = value.canonical_bytes();
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

    // ========================================================================
    // Budget golden tests
    // ========================================================================

    #[test]
    fn test_golden_budget_default() {
        let budget = construct_budget_default();
        verify_encoding(&budget, &BUDGET_DEFAULT_VECTOR);
    }

    #[test]
    fn test_golden_budget_unlimited() {
        let budget = construct_budget_unlimited();
        verify_encoding(&budget, &BUDGET_UNLIMITED_VECTOR);
    }

    #[test]
    fn test_golden_budget_minimal() {
        let budget = construct_budget_minimal();
        verify_encoding(&budget, &BUDGET_MINIMAL_VECTOR);
    }

    // ========================================================================
    // Snapshot golden tests
    // ========================================================================

    #[test]
    fn test_golden_snapshot_empty() {
        let snapshot = construct_snapshot_empty();
        verify_encoding(&snapshot, &SNAPSHOT_EMPTY_VECTOR);
    }

    #[test]
    fn test_golden_snapshot_repo_only() {
        let snapshot = construct_snapshot_repo_only();
        verify_encoding(&snapshot, &SNAPSHOT_REPO_ONLY_VECTOR);
    }

    #[test]
    fn test_golden_snapshot_full() {
        let snapshot = construct_snapshot_full();
        verify_encoding(&snapshot, &SNAPSHOT_FULL_VECTOR);
    }

    // ========================================================================
    // StopConditions golden tests
    // ========================================================================

    #[test]
    fn test_golden_stop_conditions_max_episodes() {
        let conditions = construct_stop_conditions_max_episodes();
        verify_encoding(&conditions, &STOP_CONDITIONS_MAX_EPISODES_VECTOR);
    }

    #[test]
    fn test_golden_stop_conditions_with_predicates() {
        let conditions = construct_stop_conditions_with_predicates();
        verify_encoding(&conditions, &STOP_CONDITIONS_WITH_PREDICATES_VECTOR);
    }

    // ========================================================================
    // Envelope golden tests
    // ========================================================================

    #[test]
    fn test_golden_envelope_minimal() {
        let envelope = construct_envelope_minimal();
        verify_encoding(&envelope, &ENVELOPE_MINIMAL_VECTOR);
    }

    #[test]
    fn test_golden_envelope_full() {
        let envelope = construct_envelope_full();
        verify_encoding(&envelope, &ENVELOPE_FULL_VECTOR);
    }

    #[test]
    fn test_golden_envelope_sorted_dcp_refs() {
        let envelope = construct_envelope_sorted_dcp_refs();
        verify_encoding(&envelope, &ENVELOPE_SORTED_DCP_REFS_VECTOR);
    }

    // ========================================================================
    // Stability tests
    // ========================================================================

    /// Verify that encoding is stable across multiple runs.
    #[test]
    fn test_encoding_stability() {
        for _ in 0..10 {
            let env1 = construct_envelope_minimal();
            let env2 = construct_envelope_minimal();

            let bytes1 = env1.canonical_bytes();
            let bytes2 = env2.canonical_bytes();

            assert_eq!(bytes1, bytes2, "Encoding should be stable");
        }
    }

    /// Verify that decode-encode roundtrip preserves bytes.
    #[test]
    fn test_roundtrip_stability() {
        let original = construct_envelope_full();
        let bytes1 = original.canonical_bytes();

        let decoded = EpisodeEnvelope::decode(&bytes1).expect("decode failed");
        let bytes2 = decoded.canonical_bytes();

        assert_eq!(bytes1, bytes2, "Roundtrip should preserve bytes");
    }

    /// Verify that unsorted DCP refs produce sorted canonical bytes.
    #[test]
    fn test_canonical_bytes_sorts_dcp_refs() {
        // Create envelope with unsorted DCP refs
        let envelope_unsorted = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::unlimited())
            .stop_conditions(StopConditions::max_episodes(0))
            .pinned_snapshot(PinnedSnapshot::empty())
            .context_refs(ContextRefs {
                context_pack_hash: vec![],
                dcp_refs: vec!["z".to_string(), "a".to_string(), "m".to_string()],
            })
            .build()
            .expect("valid");

        // Create envelope with sorted DCP refs
        let envelope_sorted = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::unlimited())
            .stop_conditions(StopConditions::max_episodes(0))
            .pinned_snapshot(PinnedSnapshot::empty())
            .context_refs(ContextRefs {
                context_pack_hash: vec![],
                dcp_refs: vec!["a".to_string(), "m".to_string(), "z".to_string()],
            })
            .build()
            .expect("valid");

        // Canonical bytes should be identical
        assert_eq!(
            envelope_unsorted.canonical_bytes(),
            envelope_sorted.canonical_bytes(),
            "canonical_bytes must sort DCP refs regardless of insertion order"
        );
    }

    /// Verify hash stability across serialize/deserialize cycles.
    #[test]
    fn test_hash_stability_across_cycles() {
        let original = construct_envelope_full();
        let original_digest = original.digest();

        // Multiple roundtrips should preserve digest
        let mut current = original;
        for _ in 0..5 {
            let bytes = current.canonical_bytes();
            current = EpisodeEnvelope::decode(&bytes).expect("decode failed");
            assert_eq!(
                current.digest(),
                original_digest,
                "Digest should be stable across cycles"
            );
        }
    }

    /// Property test: digest changes when any field changes.
    #[test]
    fn test_digest_changes_on_field_change() {
        let base = construct_envelope_minimal();
        let base_digest = base.digest();

        // Change episode_id
        let modified = EpisodeEnvelope::builder()
            .episode_id("ep-002")
            .actor_id("agent-007")
            .lease_id("lease-123")
            .capability_manifest_hash([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ])
            .budget(EpisodeBudget::unlimited())
            .stop_conditions(StopConditions::max_episodes(0))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build()
            .expect("valid");

        assert_ne!(
            modified.digest(),
            base_digest,
            "Digest should change when episode_id changes"
        );

        // Change actor_id
        let modified = EpisodeEnvelope::builder()
            .episode_id("ep-001")
            .actor_id("agent-008")
            .lease_id("lease-123")
            .capability_manifest_hash([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ])
            .budget(EpisodeBudget::unlimited())
            .stop_conditions(StopConditions::max_episodes(0))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build()
            .expect("valid");

        assert_ne!(
            modified.digest(),
            base_digest,
            "Digest should change when actor_id changes"
        );

        // Change capability_manifest_hash
        let modified = EpisodeEnvelope::builder()
            .episode_id("ep-001")
            .actor_id("agent-007")
            .lease_id("lease-123")
            .capability_manifest_hash([0xff; 32])
            .budget(EpisodeBudget::unlimited())
            .stop_conditions(StopConditions::max_episodes(0))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build()
            .expect("valid");

        assert_ne!(
            modified.digest(),
            base_digest,
            "Digest should change when capability_manifest_hash changes"
        );
    }
}
