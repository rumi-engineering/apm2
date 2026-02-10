//! Provider-agnostic forge interfaces.

use thiserror::Error;

use crate::github::GitHubError;

pub mod github;
pub mod types;

pub use types::{
    AuthInfo, CheckStatus, Comment, CreatePrArgs, ListPrArgs, PrDetail, PrState, PrStateFilter,
    PrSummary, UpdatePrArgs,
};

/// Errors emitted by forge providers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ForgeError {
    /// Invalid provider configuration.
    #[error("forge configuration error: {0}")]
    Configuration(String),

    /// Provider authentication failed.
    #[error("forge authentication error: {0}")]
    Authentication(String),

    /// Request transport failed.
    #[error("forge transport error: {0}")]
    Transport(String),

    /// API request failed with a structured status code.
    #[error("forge API error ({status}): {message}")]
    Api {
        /// HTTP status code returned by the forge API.
        status: u16,
        /// Error body/message.
        message: String,
    },

    /// API payload parse failed.
    #[error("forge parse error: {0}")]
    Parse(String),

    /// Requested operation is not supported by this provider.
    #[error("forge operation unsupported: {0}")]
    Unsupported(String),
}

impl From<GitHubError> for ForgeError {
    fn from(value: GitHubError) -> Self {
        Self::Authentication(value.to_string())
    }
}

impl From<reqwest::Error> for ForgeError {
    fn from(value: reqwest::Error) -> Self {
        Self::Transport(value.to_string())
    }
}

impl From<serde_json::Error> for ForgeError {
    fn from(value: serde_json::Error) -> Self {
        Self::Parse(value.to_string())
    }
}

/// Provider-agnostic forge interface.
pub trait ForgeProvider: Send + Sync {
    /// Returns the provider name.
    fn provider_name(&self) -> &'static str;

    /// Returns the repository identifier (`owner/repo`).
    fn repo_id(&self) -> &str;

    /// Lists pull requests for the repository.
    ///
    /// # Errors
    ///
    /// Returns an error when listing fails or authorization is denied.
    fn list_prs(&self, args: &ListPrArgs) -> Result<Vec<PrSummary>, ForgeError>;

    /// Returns full pull request detail.
    ///
    /// # Errors
    ///
    /// Returns an error when the pull request cannot be read.
    fn view_pr(&self, pr_number: u32) -> Result<PrDetail, ForgeError>;

    /// Creates a pull request and returns its number.
    ///
    /// # Errors
    ///
    /// Returns an error when creation fails or is unauthorized.
    fn create_pr(&self, args: &CreatePrArgs) -> Result<u32, ForgeError>;

    /// Updates an existing pull request.
    ///
    /// # Errors
    ///
    /// Returns an error when update fails or is unauthorized.
    fn update_pr(&self, pr_number: u32, args: &UpdatePrArgs) -> Result<(), ForgeError>;

    /// Enables auto-merge behavior for a pull request.
    ///
    /// # Errors
    ///
    /// Returns an error when merge/auto-merge setup fails.
    fn auto_merge(&self, pr_number: u32) -> Result<(), ForgeError>;

    /// Returns the head commit SHA for a pull request.
    ///
    /// # Errors
    ///
    /// Returns an error when the pull request cannot be read.
    fn head_sha(&self, pr_number: u32) -> Result<String, ForgeError>;

    /// Posts a comment to a pull request and returns the comment ID.
    ///
    /// # Errors
    ///
    /// Returns an error when comment publication fails.
    fn post_comment(&self, pr_number: u32, body: &str) -> Result<u64, ForgeError>;

    /// Reads pull request comments.
    ///
    /// # Errors
    ///
    /// Returns an error when comment retrieval fails.
    fn read_comments(&self, pr_number: u32, max_pages: u32) -> Result<Vec<Comment>, ForgeError>;

    /// Lists checks for a pull request.
    ///
    /// # Errors
    ///
    /// Returns an error when check retrieval fails.
    fn pr_checks(&self, pr_number: u32) -> Result<Vec<CheckStatus>, ForgeError>;

    /// Sets commit status for a commit SHA.
    ///
    /// # Errors
    ///
    /// Returns an error when status publication fails.
    fn set_commit_status(
        &self,
        sha: &str,
        state: &str,
        context: &str,
        description: &str,
    ) -> Result<(), ForgeError>;

    /// Returns provider authentication information.
    ///
    /// # Errors
    ///
    /// Returns an error when authentication cannot be verified.
    fn auth_check(&self) -> Result<AuthInfo, ForgeError>;

    /// Returns repository default branch.
    ///
    /// # Errors
    ///
    /// Returns an error when repository metadata cannot be read.
    fn default_branch(&self) -> Result<String, ForgeError>;

    /// Returns actor permission for a repository.
    ///
    /// # Errors
    ///
    /// Returns an error when permission lookup fails.
    fn actor_permission(&self, actor: &str) -> Result<String, ForgeError>;
}
