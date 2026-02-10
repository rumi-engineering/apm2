//! Provider-agnostic forge data shapes.

use serde::{Deserialize, Serialize};

/// Pull request lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrState {
    /// Pull request is open.
    Open,
    /// Pull request is closed without merge.
    Closed,
    /// Pull request is merged.
    Merged,
}

impl PrState {
    /// Returns the lowercase wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Merged => "merged",
        }
    }
}

/// Pull request list state filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrStateFilter {
    /// List open pull requests.
    Open,
    /// List closed pull requests.
    Closed,
    /// List merged pull requests.
    Merged,
    /// List both open and closed pull requests.
    All,
}

impl PrStateFilter {
    /// Returns the forge API state value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed | Self::Merged => "closed",
            Self::All => "all",
        }
    }
}

/// Arguments for listing pull requests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListPrArgs {
    /// Optional state filter.
    pub state: Option<PrStateFilter>,
    /// Optional head branch filter.
    pub head: Option<String>,
    /// Optional base branch filter.
    pub base: Option<String>,
    /// Optional result limit.
    pub limit: Option<u32>,
}

/// Arguments for creating a pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePrArgs {
    /// Pull request title.
    pub title: String,
    /// Pull request body markdown.
    pub body: String,
    /// Source branch.
    pub head: String,
    /// Target branch.
    pub base: String,
}

/// Arguments for updating a pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePrArgs {
    /// Updated pull request title.
    pub title: String,
    /// Updated pull request body markdown.
    pub body: String,
}

/// Provider-agnostic pull request summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrSummary {
    /// Pull request number.
    pub number: u32,
    /// Pull request title.
    pub title: String,
    /// Pull request state.
    pub state: PrState,
    /// Author login/name.
    pub author: String,
    /// Source branch.
    pub head_ref: String,
    /// Target branch.
    pub base_ref: String,
    /// Pull request URL.
    pub url: String,
}

/// Provider-agnostic pull request detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrDetail {
    /// Summary fields.
    pub summary: PrSummary,
    /// Pull request body markdown.
    pub body: String,
    /// Head commit SHA.
    pub head_sha: String,
    /// Forge author association value.
    pub author_association: String,
    /// Provider mergeability value.
    pub mergeable: String,
    /// Provider review decision value.
    pub review_decision: String,
    /// Label names.
    pub labels: Vec<String>,
}

/// Provider-agnostic issue/PR comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    /// Comment identifier.
    pub id: u64,
    /// Comment author login/name.
    pub author: String,
    /// Comment body.
    pub body: String,
    /// Creation timestamp (RFC3339 string).
    pub created_at: String,
}

/// Provider-agnostic check run/state summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckStatus {
    /// Check name/context.
    pub name: String,
    /// Check status value.
    pub status: String,
    /// Check conclusion value.
    pub conclusion: String,
    /// Optional check details URL.
    pub details_url: String,
}

/// Provider authentication identity details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthInfo {
    /// Provider name.
    pub provider: String,
    /// Effective principal identity.
    pub principal: String,
    /// Granted scope/permission strings.
    pub scopes: Vec<String>,
}
