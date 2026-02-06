//! Reviewer capability manifest definitions (TCK-00317).
//!
//! This module provides the canonical reviewer v0 capability manifest,
//! which defines the tool surface available to reviewer agents during
//! automated code review.
//!
//! # Security Model
//!
//! Per RFC-0019 REQ-0002:
//! - Capability manifests must be real (no empty allowlists)
//! - Manifests are stored as CAS artifacts (hash-addressed)
//! - `SpawnEpisode` loads manifests by hash
//! - Policy resolution decides which manifest hash is assigned
//!
//! # Reviewer v0 Tool Surface
//!
//! Per RFC-0019 acceptance criteria:
//! - `Read`: File reading for code review
//! - `Git`: Read-only git operations (diff, status, log)
//! - `Artifact`: Fetch review artifacts from CAS
//! - `ListFiles`: Directory listing for navigation
//! - `Search`: Content search for code analysis
//!
//! # Handler-Layer Enforcement for Git and Artifact
//!
//! While `ToolClass::Git` and `ToolClass::Artifact` have `can_mutate() == true`
//! at the type level, the reviewer manifest grants these capabilities with the
//! understanding that **read-only enforcement is performed at the handler
//! layer**:
//!
//! - `Git` capability: The git handler only allows read-only commands (diff,
//!   status, log) and rejects write commands (push, commit, checkout)
//! - `Artifact` capability: The artifact handler only allows fetch/get
//!   operations and rejects publish/put operations
//!
//! This design provides defense-in-depth:
//! 1. Manifest allowlist controls which tool classes are accessible
//! 2. Handler implementations control which operations are permitted
//! 3. Both layers must agree for an operation to proceed (fail-closed)
//!
//! # Denied Operations (fail-closed)
//!
//! - `Write`: File modifications (reviewer cannot modify code)
//! - `Execute`: Shell commands (no execution authority)
//! - `Network`: External network access (no exfiltration)
//! - `Inference`: LLM API calls (controlled by orchestrator)
//!
//! # Contract References
//!
//! - RFC-0019 REQ-0002: Capability manifests must be real
//! - RFC-0019 DEC-0005: CAS-backed manifest storage
//! - AD-TOOL-002: Capability manifests as sealed references
//! - TCK-00254: Allowlist enforcement

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::capability::{
    Capability, CapabilityError, CapabilityManifest, CapabilityManifestBuilder,
};
use super::scope::CapabilityScope;
use super::tool_class::ToolClass;

/// Manifest ID for the canonical reviewer v0 manifest.
pub const REVIEWER_V0_MANIFEST_ID: &str = "reviewer-v0";

/// Delegator ID for daemon-issued manifests.
pub const DAEMON_DELEGATOR_ID: &str = "daemon";

/// Static cache for the canonical reviewer v0 manifest.
static REVIEWER_V0_MANIFEST: OnceLock<CapabilityManifest> = OnceLock::new();

/// Static cache for the canonical reviewer v0 manifest hash.
static REVIEWER_V0_MANIFEST_HASH: OnceLock<[u8; 32]> = OnceLock::new();

/// Returns the canonical reviewer v0 capability manifest.
///
/// This manifest defines the tool surface available to reviewer agents:
/// - Read: File reading for code review
/// - Git: Read-only git operations
/// - Artifact: CAS artifact fetch
/// - `ListFiles`: Directory listing
/// - Search: Content search
///
/// The manifest is cached on first call for performance.
///
/// # Returns
///
/// A reference to the canonical reviewer v0 manifest.
#[must_use]
pub fn reviewer_v0_manifest() -> &'static CapabilityManifest {
    REVIEWER_V0_MANIFEST
        .get_or_init(|| build_reviewer_v0_manifest().expect("reviewer v0 manifest should be valid"))
}

/// Returns the BLAKE3 hash of the canonical reviewer v0 manifest.
///
/// This hash is used as the manifest identifier in policy resolution
/// and is verified when loading the manifest from CAS.
///
/// # Returns
///
/// The 32-byte BLAKE3 hash of the canonical reviewer v0 manifest.
#[must_use]
pub fn reviewer_v0_manifest_hash() -> &'static [u8; 32] {
    REVIEWER_V0_MANIFEST_HASH.get_or_init(|| reviewer_v0_manifest().digest())
}

/// Builds the canonical reviewer v0 capability manifest.
///
/// # Tool Surface Definition
///
/// Per RFC-0019 REQ-0002 acceptance criteria, the reviewer v0 manifest
/// includes:
///
/// | Tool Class | Purpose | Risk Tier |
/// |------------|---------|-----------|
/// | Read | File reading for code review | Low |
/// | Git | Read-only operations (diff, status, log) | Low |
/// | Artifact | CAS artifact fetch | Low |
/// | `ListFiles` | Directory listing | Low |
/// | Search | Content search | Low |
///
/// # Security Invariants
///
/// - [INV-TCK-00317-001] All granted capabilities are read-only
/// - [INV-TCK-00317-002] Write, Execute, Network, Inference are NOT in
///   allowlist
/// - [INV-TCK-00317-003] Manifest validates successfully on construction
///
/// # Errors
///
/// Returns an error if manifest validation fails (should not happen for
/// the canonical manifest).
pub fn build_reviewer_v0_manifest() -> Result<CapabilityManifest, CapabilityError> {
    // TCK-00352 BLOCKER 2 fix: V1 minting requires a non-zero expiry.
    // Use a deterministic far-future timestamp (2099-01-01T00:00:00Z)
    // so that the canonical manifest hash remains stable while still
    // satisfying V1 expiry requirements. Without this, V1 minting
    // always fails for the reviewer manifest, leaving sessions without
    // V1 scope enforcement (fail-open).
    const REVIEWER_V0_EXPIRY: u64 = 4_070_908_800; // 2099-01-01 UTC

    // Use a deterministic timestamp for canonical manifest
    // This ensures the manifest hash is stable across builds
    let created_at = 0u64; // Epoch timestamp for canonical version

    CapabilityManifestBuilder::new(REVIEWER_V0_MANIFEST_ID)
        .delegator(DAEMON_DELEGATOR_ID)
        .created_at(created_at)
        .expires_at(REVIEWER_V0_EXPIRY)
        // Read capability: file reading for code review
        .capability(
            Capability::builder("cap-reviewer-read", ToolClass::Read)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        // Git capability: read-only git operations
        .capability(
            Capability::builder("cap-reviewer-git", ToolClass::Git)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        // Artifact capability: CAS artifact fetch
        .capability(
            Capability::builder("cap-reviewer-artifact", ToolClass::Artifact)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        // ListFiles capability: directory listing
        .capability(
            Capability::builder("cap-reviewer-listfiles", ToolClass::ListFiles)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        // Search capability: content search
        .capability(
            Capability::builder("cap-reviewer-search", ToolClass::Search)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        // Tool allowlist: only these tool classes are permitted
        .tool_allowlist(vec![
            ToolClass::Read,
            ToolClass::Git,
            ToolClass::Artifact,
            ToolClass::ListFiles,
            ToolClass::Search,
        ])
        .build()
}

/// Creates a reviewer v0 manifest with a dynamic timestamp.
///
/// This is useful for testing when a non-canonical manifest with a
/// real timestamp is needed.
///
/// # Arguments
///
/// * `manifest_id` - Custom manifest ID
/// * `delegator_id` - Custom delegator ID
///
/// # Errors
///
/// Returns an error if manifest validation fails.
pub fn build_reviewer_v0_manifest_dynamic(
    manifest_id: &str,
    delegator_id: &str,
) -> Result<CapabilityManifest, CapabilityError> {
    // TCK-00352 BLOCKER 2 fix: dynamic manifests also need non-zero
    // expiry for V1 compatibility. Default to 24 hours from now.
    const DEFAULT_MANIFEST_TTL_SECS: u64 = 86400; // 24 hours

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let expires_at = now + DEFAULT_MANIFEST_TTL_SECS;

    CapabilityManifestBuilder::new(manifest_id)
        .delegator(delegator_id)
        .created_at(now)
        .expires_at(expires_at)
        .capability(
            Capability::builder("cap-reviewer-read", ToolClass::Read)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        .capability(
            Capability::builder("cap-reviewer-git", ToolClass::Git)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        .capability(
            Capability::builder("cap-reviewer-artifact", ToolClass::Artifact)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        .capability(
            Capability::builder("cap-reviewer-listfiles", ToolClass::ListFiles)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        .capability(
            Capability::builder("cap-reviewer-search", ToolClass::Search)
                .scope(CapabilityScope::allow_all())
                .build()?,
        )
        .tool_allowlist(vec![
            ToolClass::Read,
            ToolClass::Git,
            ToolClass::Artifact,
            ToolClass::ListFiles,
            ToolClass::Search,
        ])
        .build()
}

/// Checks if a manifest hash matches the canonical reviewer v0 manifest.
///
/// # Arguments
///
/// * `hash` - The manifest hash to check
///
/// # Returns
///
/// `true` if the hash matches the canonical reviewer v0 manifest hash.
#[must_use]
pub fn is_reviewer_v0_manifest_hash(hash: &[u8; 32]) -> bool {
    hash == reviewer_v0_manifest_hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reviewer_v0_manifest_is_valid() {
        let manifest = reviewer_v0_manifest();
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_reviewer_v0_manifest_id() {
        let manifest = reviewer_v0_manifest();
        assert_eq!(manifest.manifest_id, REVIEWER_V0_MANIFEST_ID);
    }

    #[test]
    fn test_reviewer_v0_manifest_delegator() {
        let manifest = reviewer_v0_manifest();
        assert_eq!(manifest.delegator_id, DAEMON_DELEGATOR_ID);
    }

    #[test]
    fn test_reviewer_v0_manifest_has_correct_tool_allowlist() {
        let manifest = reviewer_v0_manifest();

        // Allowed tools
        assert!(
            manifest.is_tool_allowed(ToolClass::Read),
            "Read should be allowed"
        );
        assert!(
            manifest.is_tool_allowed(ToolClass::Git),
            "Git should be allowed"
        );
        assert!(
            manifest.is_tool_allowed(ToolClass::Artifact),
            "Artifact should be allowed"
        );
        assert!(
            manifest.is_tool_allowed(ToolClass::ListFiles),
            "ListFiles should be allowed"
        );
        assert!(
            manifest.is_tool_allowed(ToolClass::Search),
            "Search should be allowed"
        );

        // Denied tools (fail-closed)
        assert!(
            !manifest.is_tool_allowed(ToolClass::Write),
            "Write should be denied"
        );
        assert!(
            !manifest.is_tool_allowed(ToolClass::Execute),
            "Execute should be denied"
        );
        assert!(
            !manifest.is_tool_allowed(ToolClass::Network),
            "Network should be denied"
        );
        assert!(
            !manifest.is_tool_allowed(ToolClass::Inference),
            "Inference should be denied"
        );
    }

    #[test]
    fn test_reviewer_v0_manifest_has_capabilities() {
        let manifest = reviewer_v0_manifest();
        assert_eq!(manifest.capabilities.len(), 5);

        // Verify capability IDs
        let cap_ids: Vec<_> = manifest
            .capabilities
            .iter()
            .map(|c| c.capability_id.as_str())
            .collect();
        assert!(cap_ids.contains(&"cap-reviewer-read"));
        assert!(cap_ids.contains(&"cap-reviewer-git"));
        assert!(cap_ids.contains(&"cap-reviewer-artifact"));
        assert!(cap_ids.contains(&"cap-reviewer-listfiles"));
        assert!(cap_ids.contains(&"cap-reviewer-search"));
    }

    #[test]
    fn test_reviewer_v0_manifest_hash_is_deterministic() {
        let hash1 = reviewer_v0_manifest_hash();
        let hash2 = reviewer_v0_manifest_hash();
        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn test_reviewer_v0_manifest_hash_matches_digest() {
        let manifest = reviewer_v0_manifest();
        let computed_hash = manifest.digest();
        let cached_hash = reviewer_v0_manifest_hash();
        assert_eq!(&computed_hash, cached_hash);
    }

    #[test]
    fn test_is_reviewer_v0_manifest_hash() {
        let hash = reviewer_v0_manifest_hash();
        assert!(is_reviewer_v0_manifest_hash(hash));

        let wrong_hash = [0u8; 32];
        assert!(!is_reviewer_v0_manifest_hash(&wrong_hash));
    }

    #[test]
    fn test_reviewer_v0_manifest_has_v1_compatible_expiry() {
        let manifest = reviewer_v0_manifest();
        // TCK-00352 BLOCKER 2 fix: V1 manifests require non-zero expiry.
        // The canonical reviewer manifest uses a deterministic far-future
        // expiry (2099-01-01 UTC) to ensure V1 minting succeeds.
        assert!(
            manifest.expires_at > 0,
            "Canonical manifest must have non-zero expiry for V1 compatibility"
        );
        assert_eq!(
            manifest.expires_at, 4_070_908_800,
            "Canonical manifest expiry must be deterministic (2099-01-01 UTC)"
        );
        assert!(!manifest.is_expired());
    }

    #[test]
    fn test_dynamic_manifest_has_timestamp() {
        let manifest = build_reviewer_v0_manifest_dynamic("test-manifest", "test-delegator")
            .expect("manifest should be valid");
        assert!(
            manifest.created_at > 0,
            "Dynamic manifest should have timestamp"
        );
        assert_eq!(manifest.manifest_id, "test-manifest");
        assert_eq!(manifest.delegator_id, "test-delegator");
    }

    #[test]
    fn test_validate_request_allows_read() {
        use std::path::PathBuf;

        use super::super::capability::ToolRequest;
        use super::super::envelope::RiskTier;

        let manifest = reviewer_v0_manifest();
        let request = ToolRequest::new(ToolClass::Read, RiskTier::default())
            .with_path(PathBuf::from("/workspace/src/lib.rs"));

        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed(), "Read request should be allowed");
    }

    #[test]
    fn test_validate_request_denies_write() {
        use std::path::PathBuf;

        use super::super::capability::ToolRequest;
        use super::super::envelope::RiskTier;

        let manifest = reviewer_v0_manifest();
        let request = ToolRequest::new(ToolClass::Write, RiskTier::default())
            .with_path(PathBuf::from("/workspace/src/lib.rs"));

        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied(), "Write request should be denied");
    }

    #[test]
    fn test_validate_request_denies_execute() {
        use super::super::capability::ToolRequest;
        use super::super::envelope::RiskTier;

        let manifest = reviewer_v0_manifest();
        let request = ToolRequest::new(ToolClass::Execute, RiskTier::default())
            .with_shell_command("rm -rf /");

        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied(), "Execute request should be denied");
    }

    #[test]
    fn test_validate_request_allows_listfiles() {
        use std::path::PathBuf;

        use super::super::capability::ToolRequest;
        use super::super::envelope::RiskTier;

        let manifest = reviewer_v0_manifest();
        let request = ToolRequest::new(ToolClass::ListFiles, RiskTier::default())
            .with_path(PathBuf::from("/workspace/src"));

        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed(), "ListFiles request should be allowed");
    }

    #[test]
    fn test_validate_request_allows_search() {
        use super::super::capability::ToolRequest;
        use super::super::envelope::RiskTier;

        let manifest = reviewer_v0_manifest();
        let request = ToolRequest::new(ToolClass::Search, RiskTier::default());

        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed(), "Search request should be allowed");
    }
}
