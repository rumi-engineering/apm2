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

use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

use crate::protocol::dispatch::{PolicyResolution, PolicyResolutionError, PolicyResolver};
use crate::protocol::messages::WorkRole;

/// Resolves policy via governance integration.
#[derive(Debug, Clone, Default)]
pub struct GovernancePolicyResolver;

impl GovernancePolicyResolver {
    /// Creates a new policy resolver.
    #[must_use]
    pub const fn new() -> Self {
        Self
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
