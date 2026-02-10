//! GitHub forge provider backed by GitHub App installation tokens.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;

use super::types::{
    AuthInfo, CheckStatus, Comment, CreatePrArgs, ListPrArgs, PrDetail, PrState, PrSummary,
    UpdatePrArgs,
};
use super::{ForgeError, ForgeProvider};
use crate::github::{
    GitHubApp, GitHubScope, RiskTier, TokenProvider, TokenRequest, validate_api_endpoint,
    validate_repository,
};

const GITHUB_API_VERSION: &str = "2022-11-28";

/// GitHub implementation of [`ForgeProvider`].
pub struct GitHubForgeProvider {
    repo: String,
    installation_id: String,
    risk_tier: RiskTier,
    episode_id: String,
    api_base_url: String,
    token_provider: Arc<dyn TokenProvider>,
    http_client: reqwest::blocking::Client,
}

impl GitHubForgeProvider {
    /// Creates a provider with the default GitHub API base URL.
    ///
    /// # Errors
    ///
    /// Returns an error if repository or API endpoint configuration is invalid.
    pub fn new(
        repo: impl Into<String>,
        installation_id: impl Into<String>,
        risk_tier: RiskTier,
        episode_id: impl Into<String>,
        token_provider: Arc<dyn TokenProvider>,
    ) -> Result<Self, ForgeError> {
        Self::new_with_api_base_url(
            repo,
            installation_id,
            risk_tier,
            episode_id,
            token_provider,
            "https://api.github.com",
        )
    }

    /// Creates a provider with an explicit API base URL.
    ///
    /// # Errors
    ///
    /// Returns an error if repository or API endpoint configuration is invalid.
    pub fn new_with_api_base_url(
        repo: impl Into<String>,
        installation_id: impl Into<String>,
        risk_tier: RiskTier,
        episode_id: impl Into<String>,
        token_provider: Arc<dyn TokenProvider>,
        api_base_url: impl Into<String>,
    ) -> Result<Self, ForgeError> {
        let repo = repo.into();
        validate_repository(&repo).map_err(|err| ForgeError::Configuration(err.to_string()))?;

        let installation_id = installation_id.into();
        if installation_id.trim().is_empty() {
            return Err(ForgeError::Configuration(
                "installation_id must not be empty".to_string(),
            ));
        }

        let api_base_url = api_base_url.into();
        if api_base_url.trim().is_empty() {
            return Err(ForgeError::Configuration(
                "api_base_url must not be empty".to_string(),
            ));
        }

        let http_client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|err| ForgeError::Transport(err.to_string()))?;

        Ok(Self {
            repo,
            installation_id,
            risk_tier,
            episode_id: episode_id.into(),
            api_base_url,
            token_provider,
            http_client,
        })
    }

    fn app_for_scopes(&self, scopes: &[GitHubScope]) -> Result<GitHubApp, ForgeError> {
        for app in [GitHubApp::Reader, GitHubApp::Developer, GitHubApp::Operator] {
            if scopes.iter().all(|scope| app.allows_scope(*scope))
                && self.risk_tier.allowed_apps().contains(&app)
            {
                return Ok(app);
            }
        }

        Err(ForgeError::Authentication(format!(
            "risk tier {} cannot mint token for requested scopes",
            self.risk_tier
        )))
    }

    fn mint_token(&self, scopes: &[GitHubScope]) -> Result<SecretString, ForgeError> {
        let app = self.app_for_scopes(scopes)?;
        let request = TokenRequest::new(
            app,
            self.installation_id.clone(),
            self.risk_tier,
            self.episode_id.clone(),
        )
        .with_scopes(scopes.to_vec());

        let response = self.token_provider.mint_token(&request)?;
        Ok(response.token)
    }

    fn build_url(&self, endpoint: &str) -> String {
        format!("{}{}", self.api_base_url.trim_end_matches('/'), endpoint)
    }

    fn send_json_request(
        &self,
        method: Method,
        endpoint: &str,
        scopes: &[GitHubScope],
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::blocking::Response, ForgeError> {
        validate_api_endpoint(endpoint)
            .map_err(|err| ForgeError::Configuration(err.to_string()))?;
        let token = self.mint_token(scopes)?;

        let mut builder = self
            .http_client
            .request(method, self.build_url(endpoint))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "apm2-core/forge-github")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .bearer_auth(token.expose_secret());

        if let Some(payload) = body {
            builder = builder.json(&payload);
        }

        builder.send().map_err(ForgeError::from)
    }

    fn parse_json_response<T: for<'de> Deserialize<'de>>(
        response: reqwest::blocking::Response,
    ) -> Result<T, ForgeError> {
        let status = response.status();
        if !status.is_success() {
            let message = response
                .text()
                .unwrap_or_else(|_| "unable to read response body".to_string());
            return Err(ForgeError::Api {
                status: status.as_u16(),
                message,
            });
        }

        response.json::<T>().map_err(ForgeError::from)
    }

    fn parse_empty_response(response: reqwest::blocking::Response) -> Result<(), ForgeError> {
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let message = response
                .text()
                .unwrap_or_else(|_| "unable to read response body".to_string());
            Err(ForgeError::Api {
                status: status.as_u16(),
                message,
            })
        }
    }

    fn state_from_rest(state: &str, merged_at: Option<&str>) -> PrState {
        match (state, merged_at) {
            ("open", _) => PrState::Open,
            (_, Some(_)) => PrState::Merged,
            _ => PrState::Closed,
        }
    }

    fn mergeable_label(value: Option<bool>) -> String {
        match value {
            Some(true) => "MERGEABLE".to_string(),
            Some(false) => "CONFLICTING".to_string(),
            None => "UNKNOWN".to_string(),
        }
    }
}

impl ForgeProvider for GitHubForgeProvider {
    fn provider_name(&self) -> &'static str {
        "github"
    }

    fn repo_id(&self) -> &str {
        &self.repo
    }

    fn list_prs(&self, args: &ListPrArgs) -> Result<Vec<PrSummary>, ForgeError> {
        let mut query: Vec<(String, String)> = Vec::new();
        if let Some(state) = args.state {
            query.push(("state".to_string(), state.as_str().to_string()));
        }
        if let Some(head) = &args.head {
            query.push(("head".to_string(), head.clone()));
        }
        if let Some(base) = &args.base {
            query.push(("base".to_string(), base.clone()));
        }
        if let Some(limit) = args.limit {
            query.push(("per_page".to_string(), limit.to_string()));
        }

        let mut endpoint = format!("/repos/{}/pulls", self.repo);
        if !query.is_empty() {
            let encoded = query
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");
            endpoint.push('?');
            endpoint.push_str(&encoded);
        }

        let response = self.send_json_request(
            Method::GET,
            &endpoint,
            &[GitHubScope::ContentsRead, GitHubScope::MetadataRead],
            None,
        )?;
        let payload: Vec<GithubPrListEntry> = Self::parse_json_response(response)?;

        Ok(payload
            .into_iter()
            .map(|entry| PrSummary {
                number: entry.number,
                title: entry.title,
                state: Self::state_from_rest(&entry.state, entry.merged_at.as_deref()),
                author: entry.user.map_or_else(String::new, |user| user.login),
                head_ref: entry.head.reference,
                base_ref: entry.base.reference,
                url: entry.html_url,
            })
            .collect())
    }

    fn view_pr(&self, pr_number: u32) -> Result<PrDetail, ForgeError> {
        let endpoint = format!("/repos/{}/pulls/{pr_number}", self.repo);
        let response = self.send_json_request(
            Method::GET,
            &endpoint,
            &[GitHubScope::ContentsRead, GitHubScope::MetadataRead],
            None,
        )?;
        let payload: GithubPrDetail = Self::parse_json_response(response)?;

        Ok(PrDetail {
            summary: PrSummary {
                number: payload.number,
                title: payload.title,
                state: Self::state_from_rest(&payload.state, payload.merged_at.as_deref()),
                author: payload.user.map_or_else(String::new, |user| user.login),
                head_ref: payload.head.reference,
                base_ref: payload.base.reference,
                url: payload.html_url,
            },
            body: payload.body.unwrap_or_default(),
            head_sha: payload.head.sha,
            author_association: payload.author_association,
            mergeable: Self::mergeable_label(payload.mergeable),
            review_decision: "UNKNOWN".to_string(),
            labels: payload.labels.into_iter().map(|label| label.name).collect(),
        })
    }

    fn create_pr(&self, args: &CreatePrArgs) -> Result<u32, ForgeError> {
        let endpoint = format!("/repos/{}/pulls", self.repo);
        let response = self.send_json_request(
            Method::POST,
            &endpoint,
            &[GitHubScope::PullRequestsWrite],
            Some(json!({
                "title": args.title.as_str(),
                "body": args.body.as_str(),
                "head": args.head.as_str(),
                "base": args.base.as_str(),
            })),
        )?;
        let payload: GithubCreatedPr = Self::parse_json_response(response)?;
        Ok(payload.number)
    }

    fn update_pr(&self, pr_number: u32, args: &UpdatePrArgs) -> Result<(), ForgeError> {
        let endpoint = format!("/repos/{}/pulls/{pr_number}", self.repo);
        let response = self.send_json_request(
            Method::PATCH,
            &endpoint,
            &[GitHubScope::PullRequestsWrite],
            Some(json!({
                "title": args.title.as_str(),
                "body": args.body.as_str(),
            })),
        )?;
        Self::parse_empty_response(response)
    }

    fn auto_merge(&self, pr_number: u32) -> Result<(), ForgeError> {
        // REST fallback: merge now using squash. This preserves current workflow
        // semantics where auto-merge is used immediately after submission.
        let endpoint = format!("/repos/{}/pulls/{pr_number}/merge", self.repo);
        let response = self.send_json_request(
            Method::PUT,
            &endpoint,
            &[GitHubScope::PullRequestsWrite],
            Some(json!({ "merge_method": "squash" })),
        )?;
        Self::parse_empty_response(response)
    }

    fn head_sha(&self, pr_number: u32) -> Result<String, ForgeError> {
        Ok(self.view_pr(pr_number)?.head_sha)
    }

    fn post_comment(&self, pr_number: u32, body: &str) -> Result<u64, ForgeError> {
        let endpoint = format!("/repos/{}/issues/{pr_number}/comments", self.repo);
        let response = self.send_json_request(
            Method::POST,
            &endpoint,
            &[GitHubScope::PullRequestsWrite],
            Some(json!({ "body": body })),
        )?;
        let payload: GithubCommentCreate = Self::parse_json_response(response)?;
        Ok(payload.id)
    }

    fn read_comments(&self, pr_number: u32, max_pages: u32) -> Result<Vec<Comment>, ForgeError> {
        let mut comments: Vec<Comment> = Vec::new();
        for page in 1..=max_pages {
            let endpoint = format!(
                "/repos/{}/issues/{pr_number}/comments?per_page=100&page={page}",
                self.repo
            );
            let response = self.send_json_request(
                Method::GET,
                &endpoint,
                &[GitHubScope::ContentsRead, GitHubScope::MetadataRead],
                None,
            )?;
            let page_comments: Vec<GithubComment> = Self::parse_json_response(response)?;
            if page_comments.is_empty() {
                break;
            }
            comments.extend(page_comments.into_iter().map(|comment| Comment {
                id: comment.id,
                author: comment.user.map_or_else(String::new, |user| user.login),
                body: comment.body,
                created_at: comment.created_at,
            }));
        }

        Ok(comments)
    }

    fn pr_checks(&self, pr_number: u32) -> Result<Vec<CheckStatus>, ForgeError> {
        let sha = self.head_sha(pr_number)?;
        let endpoint = format!("/repos/{}/commits/{sha}/check-runs", self.repo);
        let response = self.send_json_request(
            Method::GET,
            &endpoint,
            &[GitHubScope::ChecksWrite, GitHubScope::ContentsRead],
            None,
        )?;
        let payload: GithubCheckRunsResponse = Self::parse_json_response(response)?;

        Ok(payload
            .check_runs
            .into_iter()
            .map(|entry| CheckStatus {
                name: entry.name,
                status: entry.status,
                conclusion: entry.conclusion.unwrap_or_default(),
                details_url: entry.details_url.unwrap_or_default(),
            })
            .collect())
    }

    fn set_commit_status(
        &self,
        sha: &str,
        state: &str,
        context: &str,
        description: &str,
    ) -> Result<(), ForgeError> {
        let endpoint = format!("/repos/{}/statuses/{sha}", self.repo);
        let response = self.send_json_request(
            Method::POST,
            &endpoint,
            &[GitHubScope::StatusesWrite],
            Some(json!({
                "state": state,
                "context": context,
                "description": description,
            })),
        )?;
        Self::parse_empty_response(response)
    }

    fn auth_check(&self) -> Result<AuthInfo, ForgeError> {
        let response = self.send_json_request(
            Method::GET,
            "/installation",
            &[GitHubScope::MetadataRead],
            None,
        )?;
        let payload: GithubInstallation = Self::parse_json_response(response)?;

        let mut scopes = payload
            .permissions
            .map_or_else(Vec::new, |permissions| permissions.into_keys().collect());
        scopes.sort();

        Ok(AuthInfo {
            provider: "github".to_string(),
            principal: payload.account.map_or_else(String::new, |acct| acct.login),
            scopes,
        })
    }

    fn default_branch(&self) -> Result<String, ForgeError> {
        let endpoint = format!("/repos/{}", self.repo);
        let response = self.send_json_request(
            Method::GET,
            &endpoint,
            &[GitHubScope::ContentsRead, GitHubScope::MetadataRead],
            None,
        )?;
        let payload: GithubRepo = Self::parse_json_response(response)?;
        Ok(payload.default_branch)
    }

    fn actor_permission(&self, actor: &str) -> Result<String, ForgeError> {
        if actor.trim().is_empty() || actor == "unknown" {
            return Ok("none".to_string());
        }

        let endpoint = format!("/repos/{}/collaborators/{actor}/permission", self.repo);
        let response =
            self.send_json_request(Method::GET, &endpoint, &[GitHubScope::MetadataRead], None)?;

        if response.status().as_u16() == 404 {
            return Ok("none".to_string());
        }

        let payload: GithubPermission = Self::parse_json_response(response)?;
        Ok(payload.permission)
    }
}

#[derive(Debug, Deserialize)]
struct GithubUser {
    login: String,
}

#[derive(Debug, Deserialize)]
struct GithubBranchRef {
    #[serde(rename = "ref")]
    reference: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GithubLabel {
    name: String,
}

#[derive(Debug, Deserialize)]
struct GithubPrListEntry {
    number: u32,
    title: String,
    state: String,
    merged_at: Option<String>,
    user: Option<GithubUser>,
    head: GithubBranchRef,
    base: GithubBranchRef,
    html_url: String,
}

#[derive(Debug, Deserialize)]
struct GithubPrDetail {
    number: u32,
    title: String,
    state: String,
    merged_at: Option<String>,
    body: Option<String>,
    user: Option<GithubUser>,
    head: GithubBranchRef,
    base: GithubBranchRef,
    html_url: String,
    author_association: String,
    mergeable: Option<bool>,
    labels: Vec<GithubLabel>,
}

#[derive(Debug, Deserialize)]
struct GithubCreatedPr {
    number: u32,
}

#[derive(Debug, Deserialize)]
struct GithubCommentCreate {
    id: u64,
}

#[derive(Debug, Deserialize)]
struct GithubComment {
    id: u64,
    body: String,
    created_at: String,
    user: Option<GithubUser>,
}

#[derive(Debug, Deserialize)]
struct GithubCheckRun {
    name: String,
    status: String,
    conclusion: Option<String>,
    details_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubCheckRunsResponse {
    check_runs: Vec<GithubCheckRun>,
}

#[derive(Debug, Deserialize)]
struct GithubInstallationAccount {
    login: String,
}

#[derive(Debug, Deserialize)]
struct GithubInstallation {
    account: Option<GithubInstallationAccount>,
    permissions: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct GithubRepo {
    default_branch: String,
}

#[derive(Debug, Deserialize)]
struct GithubPermission {
    permission: String,
}
