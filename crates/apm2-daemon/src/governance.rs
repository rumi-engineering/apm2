//! Governance integration for policy resolution.
//!
//! This module provides the `GovernancePolicyResolver` which delegates policy
//! decisions to the Governance Holon (or local policy configuration in Phase
//! 1).
//!
//! # TCK-00289
//!
//! Implements real policy resolution wiring. Currently uses local deterministic
//! resolution until the Governance Holon is fully integrated.
//!
//! # TCK-00352
//!
//! The policy resolver is the ONLY authorized source for minting
//! `CapabilityManifestV1` instances. It holds the [`PolicyMintToken`]
//! that proves minting authority. Requester surfaces cannot obtain this
//! token.

use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

use crate::episode::capability::PolicyMintToken;
use crate::protocol::dispatch::{PolicyResolution, PolicyResolutionError, PolicyResolver};
use crate::protocol::messages::WorkRole;

/// Resolves policy via governance integration.
///
/// # TCK-00352: Policy-Only Minting Authority
///
/// This resolver is the sole holder of [`PolicyMintToken`], which is required
/// to construct
/// [`CapabilityManifestV1`](crate::episode::CapabilityManifestV1) instances.
/// The token cannot be obtained from requester surfaces.
#[derive(Debug, Clone, Default)]
pub struct GovernancePolicyResolver;

impl GovernancePolicyResolver {
    /// Creates a new policy resolver.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns a [`PolicyMintToken`] for minting `CapabilityManifestV1`.
    ///
    /// # TCK-00352: Minting Authority
    ///
    /// Only the policy resolver can create mint tokens. This method is the
    /// single point of authority for V1 manifest minting. The token proves
    /// that the caller has policy-resolver authority.
    ///
    /// # Security
    ///
    /// `PolicyMintToken::new()` is `pub(crate)`, so this method is the
    /// only way for production code to obtain a token.
    #[must_use]
    pub const fn mint_token(&self) -> PolicyMintToken {
        PolicyMintToken::new()
    }
}

impl PolicyResolver for GovernancePolicyResolver {
    fn resolve_for_claim(
        &self,
        work_id: &str,
        _role: WorkRole,
        actor_id: &str,
    ) -> Result<PolicyResolution, PolicyResolutionError> {
        // TCK-00289: In Phase 1, we use deterministic local resolution.
        // In Phase 2, this will make an IPC call to the Governance Holon.

        // Generate deterministic hashes for policy and capability manifest
        let policy_hash = blake3::hash(format!("policy:{work_id}:{actor_id}").as_bytes());
        let manifest_hash = blake3::hash(format!("manifest:{work_id}:{actor_id}").as_bytes());

        // Create and seal a context pack manifest
        let content_hash = blake3::hash(format!("content:{work_id}:{actor_id}").as_bytes());
        let context_pack = ContextPackManifestBuilder::new(
            format!("manifest:{work_id}"),
            format!("profile:{actor_id}"),
        )
        .add_entry(
            ManifestEntryBuilder::new(
                format!("/work/{work_id}/context.yaml"),
                *content_hash.as_bytes(),
            )
            .stable_id("work-context")
            .access_level(AccessLevel::Read)
            .build(),
        )
        .build();

        let context_pack_hash =
            context_pack
                .seal()
                .map_err(|e| PolicyResolutionError::GovernanceFailed {
                    message: format!("context pack sealing failed: {e}"),
                })?;

        Ok(PolicyResolution {
            policy_resolved_ref: format!("PolicyResolvedForChangeSet:{work_id}"),
            resolved_policy_hash: *policy_hash.as_bytes(),
            capability_manifest_hash: *manifest_hash.as_bytes(),
            context_pack_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::episode::capability::{CapabilityManifestV1, ManifestV1Error};
    use crate::episode::{CapabilityManifestBuilder, RiskTier, ToolClass};

    #[test]
    fn policy_resolver_provides_mint_token() {
        let resolver = GovernancePolicyResolver::new();
        let token = resolver.mint_token();

        // Token can be used to mint a V1 manifest
        let manifest = CapabilityManifestBuilder::new("gov-test")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read])
            .build()
            .unwrap();

        let result = CapabilityManifestV1::mint(token, manifest, RiskTier::Tier2, Vec::new());
        assert!(result.is_ok(), "mint with policy token should succeed");
    }

    #[test]
    fn policy_resolver_rejects_laundered_manifest() {
        let resolver = GovernancePolicyResolver::new();
        let token = resolver.mint_token();

        // Attempt to mint with no expiry (laundering attempt)
        let manifest = CapabilityManifestBuilder::new("launder-test")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(0) // No expiry!
            .tool_allowlist(vec![ToolClass::Read])
            .build()
            .unwrap();

        let result = CapabilityManifestV1::mint(token, manifest, RiskTier::Tier2, Vec::new());
        assert!(
            matches!(result, Err(ManifestV1Error::MissingExpiry)),
            "laundered manifest without expiry must be rejected"
        );
    }

    #[test]
    fn resolve_for_claim_returns_valid_resolution() {
        let resolver = GovernancePolicyResolver::new();
        let result = resolver.resolve_for_claim("W-001", WorkRole::Implementer, "agent-001");
        assert!(result.is_ok());
        let resolution = result.unwrap();
        assert!(!resolution.policy_resolved_ref.is_empty());
        assert_ne!(resolution.resolved_policy_hash, [0u8; 32]);
        assert_ne!(resolution.capability_manifest_hash, [0u8; 32]);
        assert_ne!(resolution.context_pack_hash, [0u8; 32]);
    }
}
