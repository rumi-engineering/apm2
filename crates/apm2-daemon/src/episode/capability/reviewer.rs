//! Reviewer capability manifest factory (TCK-00317).
//!
//! This module defines the standard "Reviewer v0" capability manifest, which
//! grants read-only access to the workspace and artifact retrieval.

use super::super::envelope::RiskTier;
use super::super::scope::CapabilityScope;
use super::{Capability, CapabilityManifest, ToolClass};

/// Creates the "Reviewer v0" capability manifest.
///
/// Grants:
/// - ListFiles (read-only)
/// - Search (read-only)
/// - Read (read-only)
/// - ArtifactFetch (read-only)
/// - Git (status/log only - enforced by handler logic, but granted here)
///
/// Denies:
/// - Write
/// - Execute
/// - Network
/// - Inference (until approved)
#[must_use]
pub fn reviewer_v0_manifest() -> CapabilityManifest {
    // Default scope allows access to the entire sandbox
    let scope_all = CapabilityScope::default();

    let caps = vec![
        Capability::builder("cap-reviewer-list", ToolClass::ListFiles)
            .scope(scope_all.clone())
            .risk_tier(RiskTier::Tier0)
            .build()
            .expect("valid capability"),
        Capability::builder("cap-reviewer-search", ToolClass::Search)
            .scope(scope_all.clone())
            .risk_tier(RiskTier::Tier0)
            .build()
            .expect("valid capability"),
        Capability::builder("cap-reviewer-read", ToolClass::Read)
            .scope(scope_all.clone())
            .risk_tier(RiskTier::Tier0)
            .build()
            .expect("valid capability"),
        Capability::builder("cap-reviewer-artifact", ToolClass::Artifact)
            .scope(scope_all.clone())
            .risk_tier(RiskTier::Tier0)
            .build()
            .expect("valid capability"),
        Capability::builder("cap-reviewer-git", ToolClass::Git)
            .scope(scope_all.clone())
            .risk_tier(RiskTier::Tier0)
            .build()
            .expect("valid capability"),
    ];

    let tool_allowlist = vec![
        ToolClass::ListFiles,
        ToolClass::Search,
        ToolClass::Read,
        ToolClass::Artifact,
        ToolClass::Git,
    ];

    CapabilityManifest::builder("manifest-reviewer-v0")
        .delegator("system:governance")
        .capabilities(caps)
        .tool_allowlist(tool_allowlist)
        .build()
        .expect("valid manifest")
}
