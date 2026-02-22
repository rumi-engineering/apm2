//! Golden test vectors for HSI Contract Manifest determinism verification.
//!
//! This module contains golden vectors that verify the deterministic encoding
//! of the `HSIContractManifestV1` artifact. Each vector consists of:
//!
//! 1. A manifest constructed from the dispatch registry
//! 2. The expected domain-separated BLAKE3 hash (hex-encoded)
//!
//! Hash-only vectors are sufficient because the content hash is computed from
//! the canonical bytes via domain-separated BLAKE3; if the canonical bytes
//! change, the hash changes. Full canonical-bytes vectors are not stored
//! because they are large and volatile (any route addition changes them).
//!
//! # Purpose
//!
//! Golden vectors serve multiple purposes:
//!
//! - **Determinism verification**: Ensure encoding produces identical bytes
//!   across versions, platforms, and library updates
//! - **Contract stability**: Verify that `cli_contract_hash` is stable when
//!   dispatch registry is unchanged
//! - **Cross-platform consistency**: Ensure wire format is consistent
//!   regardless of compilation target
//!
//! # Contract References
//!
//! - RFC-0020 section 3.1: `HSIContractManifestV1`
//! - RFC-0020 section 3.1.1: Generation and determinism
//! - RFC-0020 section 1.5.2: Domain separation
//! - REQ-0001: Manifest generation deterministic across repeat builds
//! - EVID-0001: HSI contract manifest determinism evidence

/// A golden test vector for the HSI contract manifest.
///
/// Each vector stores only the expected domain-separated BLAKE3 hash
/// (hex-encoded, without the `blake3:` prefix). The hash is sufficient
/// to detect any change in canonical bytes because it is computed from
/// those bytes via domain-separated BLAKE3.
pub struct GoldenVector {
    /// Human-readable name for the vector.
    pub name: &'static str,
    /// Contract reference.
    pub contract: &'static str,
    /// Expected domain-separated BLAKE3 hash (hex-encoded, no `blake3:`
    /// prefix).
    pub expected_hash: &'static str,
}

/// Golden vector: full manifest from dispatch registry with test CLI version.
///
/// This vector pins the manifest hash for the current dispatch registry.
/// If the registry changes (routes added/removed/modified), this hash
/// MUST be updated intentionally.
pub const MANIFEST_FULL_VECTOR: GoldenVector = GoldenVector {
    name: "manifest_full_registry",
    contract: "CTR-0001",
    // This hash is computed from the full dispatch registry with test CLI
    // version "0.9.0" and zero build hash. It MUST be updated when routes
    // are added, removed, or their semantics change.
    //
    // Updated: shutdown and credential management routes reclassified from
    // advisory to authoritative with receipt_required per RFC-0020 section 1.3
    // (they perform real side effects). SubscribePulse and UnsubscribePulse
    // added to SessionMessageType::all_request_variants() (deduplicated).
    // TCK-00635: OpenWork (hsi.work.open) added as authoritative+idempotent+receipt.
    // TCK-00638: PublishWorkContextEntry (hsi.work_context.publish) added as
    // authoritative+idempotent+receipt.
    // TCK-00637: ClaimWorkV2 (hsi.work.claim_v2) added as authoritative+idempotent+receipt.
    // TCK-00639: RecordWorkPrAssociation (hsi.work.record_pr_association) added as
    // authoritative+idempotent+receipt.
    expected_hash: "059693879b0eecd208b979b9cb14f22dd2c6200556a56c8806f9181251f76c79",
};

/// Golden vector: minimal manifest with a single route.
///
/// This vector pins the encoding format for a minimal manifest. It is
/// independent of the dispatch registry and should rarely change.
pub const MANIFEST_MINIMAL_VECTOR: GoldenVector = GoldenVector {
    name: "manifest_minimal_single_route",
    contract: "CTR-0001",
    // Computed from a single-route manifest with known fields.
    expected_hash: "4c6a6f64a3fd26e1e4b6447d0f64784be8e7135dfdc6c588758f4412478ac5d6",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsi_contract::manifest::*;
    use crate::hsi_contract::registry::build_manifest;

    fn test_cli_version() -> CliVersion {
        CliVersion {
            semver: "0.9.0".to_string(),
            build_hash: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        }
    }

    fn minimal_manifest() -> HsiContractManifestV1 {
        HsiContractManifestV1 {
            schema: SCHEMA_ID.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            cli_version: CliVersion {
                semver: "1.0.0".to_string(),
                build_hash:
                    "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
            },
            routes: vec![HsiRouteEntry {
                id: "TEST_ROUTE".to_string(),
                route: "hsi.test.route".to_string(),
                stability: StabilityClass::Stable,
                request_schema: "apm2.test_request.v1".to_string(),
                response_schema: "apm2.test_response.v1".to_string(),
                semantics: HsiRouteSemantics {
                    authoritative: true,
                    idempotency: IdempotencyRequirement::Required,
                    receipt_required: true,
                },
            }],
        }
    }

    /// Prints the actual hashes for updating golden vectors.
    ///
    /// Run with `cargo test -p apm2-daemon golden_vector_discovery --
    /// --nocapture` to see the hash values that should be placed in the
    /// golden vectors.
    #[test]
    fn golden_vector_discovery() {
        let full_manifest =
            build_manifest(test_cli_version()).expect("manifest build must succeed");
        let full_hash = full_manifest
            .content_hash()
            .expect("content hash must succeed");
        let full_hex = &full_hash[7..]; // strip "blake3:" prefix
        eprintln!("=== GOLDEN VECTOR DISCOVERY ===");
        eprintln!("Full manifest hash:    {full_hex}");
        eprintln!("Full manifest routes:  {}", full_manifest.routes.len());

        let min_manifest = minimal_manifest();
        let min_hash = min_manifest
            .content_hash()
            .expect("content hash must succeed");
        let min_hex = &min_hash[7..];
        eprintln!("Minimal manifest hash: {min_hex}");
    }

    #[test]
    fn full_manifest_determinism() {
        let m1 = build_manifest(test_cli_version()).expect("build 1");
        let m2 = build_manifest(test_cli_version()).expect("build 2");
        assert_eq!(
            m1.content_hash().expect("hash 1"),
            m2.content_hash().expect("hash 2"),
            "manifest hash must be deterministic across builds"
        );
        assert_eq!(
            m1.canonical_bytes().expect("bytes 1"),
            m2.canonical_bytes().expect("bytes 2"),
            "canonical bytes must be deterministic across builds"
        );
    }

    #[test]
    fn full_manifest_golden_hash() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let hash = manifest.content_hash().expect("content hash must succeed");
        let hex = &hash[7..]; // strip "blake3:"
        assert_eq!(
            hex, MANIFEST_FULL_VECTOR.expected_hash,
            "full manifest golden hash mismatch -- did the dispatch registry change? \
             Update MANIFEST_FULL_VECTOR.expected_hash if the change is intentional."
        );
    }

    #[test]
    fn minimal_manifest_golden_hash() {
        let manifest = minimal_manifest();
        let hash = manifest.content_hash().expect("content hash must succeed");
        let hex = &hash[7..];
        assert_eq!(
            hex, MANIFEST_MINIMAL_VECTOR.expected_hash,
            "minimal manifest golden hash mismatch -- did the encoding format change? \
             Update MANIFEST_MINIMAL_VECTOR.expected_hash if the change is intentional."
        );
    }

    #[test]
    fn canonical_bytes_are_nonempty() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let bytes = manifest
            .canonical_bytes()
            .expect("canonical bytes must succeed");
        assert!(
            bytes.len() > 100,
            "canonical bytes too short: {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn content_hash_is_valid_blake3() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let hash = manifest.content_hash().expect("content hash must succeed");
        assert!(hash.starts_with("blake3:"), "hash must start with blake3:");
        let hex = &hash[7..];
        assert_eq!(hex.len(), 64, "BLAKE3 hex must be 64 chars");
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be valid hex"
        );
    }

    #[test]
    fn content_hash_bytes_matches_text() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let hash_text = manifest.content_hash().expect("text hash must succeed");
        let hash_bytes = manifest
            .content_hash_bytes()
            .expect("bytes hash must succeed");
        let hex_from_bytes = hex::encode(hash_bytes);
        assert_eq!(
            &hash_text[7..],
            hex_from_bytes,
            "text and bytes hash forms must match"
        );
    }

    /// Verifies that the EVID-0001 evidence artifact contains the current
    /// golden vector hash. This prevents the evidence artifact from drifting
    /// out of sync with the actual golden vector constant.
    ///
    /// If this test fails, update the hash in
    /// `documents/rfcs/RFC-0020/evidence_artifacts/EVID-0001.yaml` to match
    /// `MANIFEST_FULL_VECTOR.expected_hash`.
    #[test]
    fn evid_0001_hash_matches_golden_vector() {
        let evid_contents =
            include_str!("../../../../documents/rfcs/RFC-0020/evidence_artifacts/EVID-0001.yaml");
        assert!(
            evid_contents.contains(MANIFEST_FULL_VECTOR.expected_hash),
            "EVID-0001.yaml does not contain the current full manifest golden hash \
             '{}'. Update the evidence artifact to match MANIFEST_FULL_VECTOR.expected_hash.",
            MANIFEST_FULL_VECTOR.expected_hash,
        );
        assert!(
            evid_contents.contains(MANIFEST_MINIMAL_VECTOR.expected_hash),
            "EVID-0001.yaml does not contain the current minimal manifest golden hash \
             '{}'. Update the evidence artifact to match MANIFEST_MINIMAL_VECTOR.expected_hash.",
            MANIFEST_MINIMAL_VECTOR.expected_hash,
        );
    }
}
