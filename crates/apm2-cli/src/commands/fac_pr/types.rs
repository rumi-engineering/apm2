//! Shared response types for `apm2 fac pr` subcommands.

use serde::{Deserialize, Serialize};

// ── PR list ────────────────────────────────────────────────────────────────

/// A single entry from provider PR list operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrListEntry {
    pub number: u32,
    pub title: String,
    pub state: String,
    #[serde(rename = "headRefName")]
    pub head_ref_name: String,
    #[serde(rename = "baseRefName")]
    pub base_ref_name: String,
    #[serde(default)]
    pub url: String,
}

/// Filter arguments for `pr list`.
#[derive(Debug, Clone, Default)]
pub struct PrListArgs {
    pub state: Option<String>,
    pub head: Option<String>,
    pub base: Option<String>,
    pub limit: Option<u32>,
}

// ── PR view ────────────────────────────────────────────────────────────────

/// Full PR view data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrViewData {
    pub number: u32,
    pub title: String,
    pub state: String,
    pub body: String,
    #[serde(rename = "headRefName")]
    pub head_ref_name: String,
    #[serde(rename = "baseRefName")]
    pub base_ref_name: String,
    #[serde(rename = "headRefOid")]
    pub head_ref_oid: String,
    pub url: String,
    #[serde(rename = "authorAssociation", default)]
    pub author_association: String,
    #[serde(default)]
    pub author: PrAuthor,
    #[serde(rename = "mergeable", default)]
    pub mergeable: String,
    #[serde(rename = "reviewDecision", default)]
    pub review_decision: String,
    #[serde(default)]
    pub labels: Vec<PrLabel>,
}

/// PR author.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PrAuthor {
    pub login: String,
}

/// PR label.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrLabel {
    pub name: String,
}

// ── Check status ───────────────────────────────────────────────────────────

/// A single CI check status entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckStatus {
    pub name: String,
    pub status: String,
    pub conclusion: String,
    #[serde(rename = "detailsUrl", default)]
    pub details_url: String,
}

// ── PR comment ─────────────────────────────────────────────────────────────

/// A single PR/issue comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrComment {
    pub id: u64,
    pub body: String,
    #[serde(default)]
    pub author: CommentAuthor,
    #[serde(rename = "createdAt", default)]
    pub created_at: String,
}

/// Comment author.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CommentAuthor {
    pub login: String,
}

// ── Auth info ──────────────────────────────────────────────────────────────

/// Forge provider authentication info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthInfo {
    pub authenticated: bool,
    pub login: String,
}

// ── Comment creation result ────────────────────────────────────────────────

/// Result of posting a PR comment via REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentCreateResult {
    pub id: u64,
}
