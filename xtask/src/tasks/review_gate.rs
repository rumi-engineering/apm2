//! Implementation of the `review-gate` command.
//!
//! This command enforces authoritative AI review gating for pull requests:
//! - Verifies `ai-review/security` and `ai-review/code-quality` commit statuses
//! - Parses machine-readable metadata from PR comments
//! - Enforces exact PR number + head SHA binding
//! - Enforces trusted reviewer identity allowlists
//! - Rejects conflicting PASS/FAIL timelines when the newest verdict is FAIL

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use xshell::{Shell, cmd};

const SECURITY_CONTEXT: &str = "ai-review/security";
const QUALITY_CONTEXT: &str = "ai-review/code-quality";

const TRUSTED_REVIEWER_SCHEMA: &str = "apm2.trusted_reviewers.v1";
const REVIEW_METADATA_SCHEMA: &str = "apm2.review.metadata.v1";
const SECURITY_METADATA_MARKER: &str = "<!-- apm2-review-metadata:v1:security -->";
const QUALITY_METADATA_MARKER: &str = "<!-- apm2-review-metadata:v1:code-quality -->";
const DEFAULT_TRUSTED_REVIEWERS_PATH: &str = ".github/review-gate/trusted-reviewers.json";

/// Runs the review gate evaluator for a PR.
pub fn run(
    repo: Option<&str>,
    pr_number: u64,
    expected_head_sha: Option<&str>,
    trusted_reviewers_path: Option<&str>,
) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    let owner_repo = match repo {
        Some(value) => value.to_string(),
        None => resolve_owner_repo(&sh)?,
    };

    let reviewers_path = trusted_reviewers_path.unwrap_or(DEFAULT_TRUSTED_REVIEWERS_PATH);
    let trusted_reviewers =
        TrustedReviewerConfig::load(Path::new(reviewers_path))?.to_allowlist_map()?;

    let pr_head_sha = fetch_pr_head_sha(&sh, &owner_repo, pr_number)?;
    if let Some(expected) = expected_head_sha
        && !expected.eq_ignore_ascii_case(&pr_head_sha)
    {
        bail!(
            "Provided head SHA mismatch for PR #{pr_number}: expected {expected}, actual {pr_head_sha}"
        );
    }

    let statuses = fetch_commit_statuses(&sh, &owner_repo, &pr_head_sha)?;
    let comments = fetch_pr_issue_comments(&sh, &owner_repo, pr_number)?;

    let input = GateEvaluationInput {
        pr_number,
        head_sha: &pr_head_sha,
        statuses: &statuses,
        comments: &comments,
        trusted_reviewers: &trusted_reviewers,
    };
    let evaluation = evaluate_gate(&input);

    println!(
        "{}",
        serde_json::to_string_pretty(&evaluation)
            .context("Failed to serialize review gate evaluation to JSON")?
    );

    if evaluation.overall_pass {
        println!("Review gate: PASS");
        Ok(())
    } else {
        bail!("Review gate: FAIL");
    }
}

fn resolve_owner_repo(sh: &Shell) -> Result<String> {
    let remote_url = cmd!(sh, "git remote get-url origin")
        .read()
        .context("Failed to read origin remote URL")?;

    parse_owner_repo(remote_url.trim()).ok_or_else(|| {
        anyhow::anyhow!(
            "Could not determine owner/repo from origin URL: {}",
            remote_url.trim()
        )
    })
}

fn parse_owner_repo(remote_url: &str) -> Option<String> {
    if let Some(rest) = remote_url.strip_prefix("git@github.com:") {
        return Some(rest.trim_end_matches(".git").to_string());
    }
    if let Some(rest) = remote_url.strip_prefix("https://github.com/") {
        return Some(rest.trim_end_matches(".git").to_string());
    }
    if let Some(rest) = remote_url.strip_prefix("http://github.com/") {
        return Some(rest.trim_end_matches(".git").to_string());
    }
    None
}

fn fetch_pr_head_sha(sh: &Shell, owner_repo: &str, pr_number: u64) -> Result<String> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    let output = cmd!(sh, "gh api {endpoint}")
        .read()
        .with_context(|| format!("Failed to fetch PR #{pr_number} metadata from GitHub"))?;

    let response: PullRequestResponse = serde_json::from_str(&output)
        .with_context(|| format!("Failed to parse PR metadata JSON for PR #{pr_number}"))?;

    if !is_valid_sha(&response.head.sha) {
        bail!(
            "PR #{pr_number} returned invalid head SHA: {}",
            response.head.sha
        );
    }

    Ok(response.head.sha)
}

fn fetch_commit_statuses(
    sh: &Shell,
    owner_repo: &str,
    head_sha: &str,
) -> Result<Vec<NormalizedStatus>> {
    let endpoint = format!("/repos/{owner_repo}/commits/{head_sha}/status");
    let output = cmd!(sh, "gh api {endpoint}")
        .read()
        .with_context(|| format!("Failed to fetch commit status for {owner_repo}@{head_sha}"))?;

    let response: CommitStatusResponse = serde_json::from_str(&output)
        .with_context(|| format!("Failed to parse commit status payload for {head_sha}"))?;

    response
        .statuses
        .into_iter()
        .map(NormalizedStatus::try_from)
        .collect()
}

fn fetch_pr_issue_comments(
    sh: &Shell,
    owner_repo: &str,
    pr_number: u64,
) -> Result<Vec<IssueComment>> {
    let mut all_comments = Vec::new();
    let mut page: u32 = 1;

    loop {
        let endpoint =
            format!("/repos/{owner_repo}/issues/{pr_number}/comments?per_page=100&page={page}");
        let output = cmd!(sh, "gh api {endpoint}")
            .read()
            .with_context(|| format!("Failed to fetch comments page {page} for PR #{pr_number}"))?;

        let page_comments: Vec<IssueComment> =
            serde_json::from_str(&output).with_context(|| {
                format!("Failed to parse PR comment payload page {page} for PR #{pr_number}")
            })?;

        if page_comments.is_empty() {
            break;
        }

        all_comments.extend(page_comments);
        page += 1;
    }

    Ok(all_comments)
}

fn evaluate_gate(input: &GateEvaluationInput<'_>) -> GateEvaluation {
    let security = evaluate_category(input, ReviewCategory::Security);
    let code_quality = evaluate_category(input, ReviewCategory::CodeQuality);

    GateEvaluation {
        overall_pass: security.pass && code_quality.pass,
        security,
        code_quality,
    }
}

fn evaluate_category(
    input: &GateEvaluationInput<'_>,
    category: ReviewCategory,
) -> CategoryEvaluation {
    let mut reasons = Vec::new();
    let context = category.status_context();

    let artifacts = collect_category_artifacts(input, category);
    if artifacts.is_empty() {
        reasons.push(format!(
            "No machine-readable review artifacts found for {}",
            category.display_name()
        ));
    }

    let latest_status = latest_status_for_context(input.statuses, context);
    let status_state = latest_status.map(|status| status.state.clone());
    if latest_status.is_none() {
        reasons.push(format!("Missing commit status context `{context}`"));
    }

    let latest_artifact = artifacts.last();
    let (authoritative_verdict, authoritative_comment_id) = match latest_artifact {
        Some(artifact) if artifact.rejection_reason.is_none() => {
            (artifact.verdict, Some(artifact.comment_id))
        },
        Some(artifact) => {
            reasons.push(format!(
                "Newest {} artifact (comment #{}) rejected: {}",
                category.display_name(),
                artifact.comment_id,
                artifact
                    .rejection_reason
                    .as_deref()
                    .unwrap_or("unknown rejection")
            ));
            (None, Some(artifact.comment_id))
        },
        None => (None, None),
    };

    if let Some(verdict) = authoritative_verdict {
        if verdict == ReviewVerdict::Fail {
            reasons.push(format!(
                "Newest {} artifact verdict is FAIL",
                category.display_name()
            ));
        }

        let valid_artifacts: Vec<&CategoryArtifact> = artifacts
            .iter()
            .filter(|artifact| artifact.rejection_reason.is_none())
            .collect();

        let has_pass = valid_artifacts
            .iter()
            .any(|artifact| artifact.verdict == Some(ReviewVerdict::Pass));
        let has_fail = valid_artifacts
            .iter()
            .any(|artifact| artifact.verdict == Some(ReviewVerdict::Fail));
        if has_pass && has_fail && verdict == ReviewVerdict::Fail {
            reasons.push(format!(
                "Conflicting PASS/FAIL artifacts for {}; newest valid artifact is FAIL",
                category.display_name()
            ));
        }

        if let Some(status) = latest_status {
            let normalized_state = status.state.to_ascii_lowercase();
            match normalized_state.as_str() {
                "success" | "failure" => {
                    let expected_state = match verdict {
                        ReviewVerdict::Pass => "success",
                        ReviewVerdict::Fail => "failure",
                    };
                    if normalized_state != expected_state {
                        reasons.push(format!(
                            "Status mismatch for {}: context `{context}` is `{normalized_state}` but authoritative verdict requires `{expected_state}`",
                            category.display_name()
                        ));
                    }
                },
                _ => {
                    reasons.push(format!(
                        "Status context `{context}` must be success/failure, got `{normalized_state}`"
                    ));
                },
            }
        }
    }

    CategoryEvaluation {
        pass: reasons.is_empty(),
        authoritative_verdict,
        authoritative_comment_id,
        status_state,
        reasons,
    }
}

fn latest_status_for_context<'a>(
    statuses: &'a [NormalizedStatus],
    context: &str,
) -> Option<&'a NormalizedStatus> {
    statuses
        .iter()
        .filter(|status| status.context == context)
        .max_by_key(|status| status.created_at)
}

fn collect_category_artifacts(
    input: &GateEvaluationInput<'_>,
    category: ReviewCategory,
) -> Vec<CategoryArtifact> {
    let mut artifacts = Vec::new();

    for comment in input.comments {
        if let Some(comment_category) =
            detect_marker_category(comment.body.as_deref().unwrap_or(""))
        {
            if comment_category != category {
                continue;
            }

            // MAJOR-1 fix: prefilter by trusted author identity.
            // Only comments whose author is in the trusted reviewer allowlist
            // for this category participate in authoritative artifact selection.
            if !is_trusted_author(input.trusted_reviewers, category, &comment.user.login) {
                eprintln!(
                    "review-gate: skipping marker comment #{} from untrusted author `{}`",
                    comment.id, comment.user.login
                );
                continue;
            }

            let timestamp = parse_comment_timestamp(comment).map_err(|error| error.to_string());
            let parsed_metadata = parse_comment_metadata(comment, category);

            let artifact = match (timestamp, parsed_metadata) {
                (Err(error), _) => CategoryArtifact {
                    comment_id: comment.id,
                    updated_at: rejected_artifact_timestamp(),
                    verdict: None,
                    rejection_reason: Some(format!("invalid timestamp: {error}")),
                },
                (Ok(updated_at), Err(error)) => CategoryArtifact {
                    comment_id: comment.id,
                    updated_at,
                    verdict: None,
                    rejection_reason: Some(error),
                },
                (Ok(updated_at), Ok(metadata)) => {
                    evaluate_metadata_for_category(input, comment, &metadata, updated_at, category)
                },
            };

            artifacts.push(artifact);
        }
    }

    artifacts.sort_by_key(|artifact| (artifact.updated_at, artifact.comment_id));
    artifacts
}

fn rejected_artifact_timestamp() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("9999-12-31T23:59:59Z")
        .expect("hard-coded RFC3339 timestamp is valid")
        .with_timezone(&Utc)
}

fn parse_comment_metadata(
    comment: &IssueComment,
    category: ReviewCategory,
) -> Result<ReviewMetadataV1, String> {
    let body = comment.body.as_deref().unwrap_or_default();
    let marker = category.marker();
    let marker_index = body
        .find(marker)
        .ok_or_else(|| "marker not present".to_string())?;

    let json = extract_json_after_marker(body, marker, marker_index)?;
    let metadata: ReviewMetadataV1 = serde_json::from_str(&json)
        .map_err(|error| format!("metadata JSON parse failed: {error}"))?;

    metadata.validate(category)
}

fn evaluate_metadata_for_category(
    input: &GateEvaluationInput<'_>,
    comment: &IssueComment,
    metadata: &ReviewMetadataV1,
    updated_at: DateTime<Utc>,
    category: ReviewCategory,
) -> CategoryArtifact {
    let trust_check = validate_reviewer_trust(
        input.trusted_reviewers,
        category,
        &metadata.reviewer_id,
        &comment.user.login,
    );

    let rejection_reason = trust_check.err().or_else(|| {
        if metadata.pr_number != input.pr_number {
            Some(format!(
                "pr_number mismatch: artifact has {}, expected {}",
                metadata.pr_number, input.pr_number
            ))
        } else if !metadata.head_sha.eq_ignore_ascii_case(input.head_sha) {
            Some(format!(
                "head_sha mismatch: artifact has {}, expected {}",
                metadata.head_sha, input.head_sha
            ))
        } else {
            None
        }
    });

    CategoryArtifact {
        comment_id: comment.id,
        updated_at,
        verdict: rejection_reason.is_none().then_some(metadata.verdict),
        rejection_reason,
    }
}

fn validate_reviewer_trust(
    trusted_reviewers: &TrustedReviewerMap,
    category: ReviewCategory,
    reviewer_id: &str,
    comment_login: &str,
) -> std::result::Result<(), String> {
    let Some(reviewers_by_id) = trusted_reviewers.get(&category) else {
        return Err(format!(
            "trusted reviewer allowlist missing category {}",
            category.display_name()
        ));
    };

    let normalized_reviewer_id = reviewer_id.to_ascii_lowercase();
    let Some(allowed_logins) = reviewers_by_id.get(&normalized_reviewer_id) else {
        return Err(format!(
            "reviewer_id `{reviewer_id}` is not allowlisted for {}",
            category.display_name()
        ));
    };

    let normalized_login = comment_login.to_ascii_lowercase();
    if !allowed_logins.contains(&normalized_login) {
        return Err(format!(
            "comment author `{comment_login}` is not allowlisted for reviewer_id `{reviewer_id}`"
        ));
    }

    Ok(())
}

/// Returns `true` if `comment_login` appears in ANY trusted reviewer entry
/// for the given `category`. This is used as a prefilter — comments from
/// untrusted authors are silently skipped before metadata parsing so that
/// forged marker comments cannot induce false gate failures (MAJOR-1).
fn is_trusted_author(
    trusted_reviewers: &TrustedReviewerMap,
    category: ReviewCategory,
    comment_login: &str,
) -> bool {
    let Some(reviewers_by_id) = trusted_reviewers.get(&category) else {
        return false;
    };

    let normalized_login = comment_login.to_ascii_lowercase();
    reviewers_by_id
        .values()
        .any(|logins| logins.contains(&normalized_login))
}

fn parse_comment_timestamp(comment: &IssueComment) -> Result<DateTime<Utc>> {
    let value = if comment.updated_at.trim().is_empty() {
        comment.created_at.trim()
    } else {
        comment.updated_at.trim()
    };

    if value.is_empty() {
        bail!("comment is missing both updated_at and created_at timestamps");
    }

    DateTime::parse_from_rfc3339(value)
        .map(|datetime| datetime.with_timezone(&Utc))
        .with_context(|| format!("invalid RFC3339 timestamp: {value}"))
}

fn detect_marker_category(body: &str) -> Option<ReviewCategory> {
    let security = body.find(SECURITY_METADATA_MARKER);
    let quality = body.find(QUALITY_METADATA_MARKER);

    match (security, quality) {
        (Some(index), Some(other)) => {
            if index <= other {
                Some(ReviewCategory::Security)
            } else {
                Some(ReviewCategory::CodeQuality)
            }
        },
        (Some(_), None) => Some(ReviewCategory::Security),
        (None, Some(_)) => Some(ReviewCategory::CodeQuality),
        (None, None) => None,
    }
}

fn extract_json_after_marker(
    body: &str,
    marker: &str,
    marker_index: usize,
) -> Result<String, String> {
    let tail = &body[marker_index + marker.len()..];
    let fence_start = tail.find("```").ok_or_else(|| {
        "metadata marker present but JSON code block start fence missing".to_string()
    })?;

    let after_fence = &tail[fence_start + 3..];
    let newline = after_fence
        .find('\n')
        .ok_or_else(|| "metadata code fence missing newline after language tag".to_string())?;

    let fenced_body = &after_fence[newline + 1..];
    let fence_end = fenced_body
        .find("```")
        .ok_or_else(|| "metadata JSON code block missing closing fence".to_string())?;

    let json = fenced_body[..fence_end].trim();
    if json.is_empty() {
        return Err("metadata JSON code block is empty".to_string());
    }

    Ok(json.to_string())
}

fn is_valid_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ReviewCategory {
    Security,
    #[serde(rename = "code-quality")]
    CodeQuality,
}

impl ReviewCategory {
    const fn status_context(self) -> &'static str {
        match self {
            Self::Security => SECURITY_CONTEXT,
            Self::CodeQuality => QUALITY_CONTEXT,
        }
    }

    const fn display_name(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::CodeQuality => "code-quality",
        }
    }

    const fn marker(self) -> &'static str {
        match self {
            Self::Security => SECURITY_METADATA_MARKER,
            Self::CodeQuality => QUALITY_METADATA_MARKER,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ReviewVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SeverityCounts {
    blocker: u32,
    major: u32,
    minor: u32,
    nit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewMetadataV1 {
    schema: String,
    review_type: ReviewCategory,
    pr_number: u64,
    head_sha: String,
    verdict: ReviewVerdict,
    severity_counts: SeverityCounts,
    reviewer_id: String,
}

impl ReviewMetadataV1 {
    fn validate(self, expected_category: ReviewCategory) -> Result<Self, String> {
        if self.schema != REVIEW_METADATA_SCHEMA {
            return Err(format!(
                "invalid metadata schema: expected `{REVIEW_METADATA_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if self.review_type != expected_category {
            return Err(format!(
                "metadata review_type `{}` does not match marker `{}`",
                self.review_type.display_name(),
                expected_category.display_name()
            ));
        }
        if !is_valid_sha(&self.head_sha) {
            return Err(format!(
                "metadata head_sha is not a 40-hex SHA: {}",
                self.head_sha
            ));
        }
        if self.reviewer_id.trim().is_empty() {
            return Err("metadata reviewer_id must not be empty".to_string());
        }

        Ok(self)
    }
}

type TrustedReviewerMap = HashMap<ReviewCategory, HashMap<String, BTreeSet<String>>>;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedReviewerConfig {
    schema: String,
    reviewers: TrustedReviewerCategories,
}

impl TrustedReviewerConfig {
    fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).with_context(|| {
            format!(
                "Failed to read trusted reviewer allowlist from {}",
                path.display()
            )
        })?;
        serde_json::from_str(&content).with_context(|| {
            format!(
                "Failed to parse trusted reviewer allowlist JSON from {}",
                path.display()
            )
        })
    }

    fn to_allowlist_map(&self) -> Result<TrustedReviewerMap> {
        if self.schema != TRUSTED_REVIEWER_SCHEMA {
            bail!(
                "Invalid trusted reviewer schema: expected `{TRUSTED_REVIEWER_SCHEMA}`, got `{}`",
                self.schema
            );
        }

        let mut map = HashMap::new();
        map.insert(
            ReviewCategory::Security,
            build_reviewer_index(&self.reviewers.security, ReviewCategory::Security)?,
        );
        map.insert(
            ReviewCategory::CodeQuality,
            build_reviewer_index(&self.reviewers.code_quality, ReviewCategory::CodeQuality)?,
        );

        Ok(map)
    }
}

fn build_reviewer_index(
    entries: &[TrustedReviewer],
    category: ReviewCategory,
) -> Result<HashMap<String, BTreeSet<String>>> {
    if entries.is_empty() {
        bail!(
            "Trusted reviewer allowlist for {} must not be empty",
            category.display_name()
        );
    }

    let mut by_id = HashMap::new();
    for entry in entries {
        if entry.reviewer_id.trim().is_empty() {
            bail!(
                "Trusted reviewer entry in {} has an empty reviewer_id",
                category.display_name()
            );
        }
        if entry.github_logins.is_empty() {
            bail!(
                "Trusted reviewer `{}` in {} has no github_logins",
                entry.reviewer_id,
                category.display_name()
            );
        }

        let key = entry.reviewer_id.to_ascii_lowercase();
        if by_id.contains_key(&key) {
            bail!(
                "Duplicate reviewer_id `{}` in {} allowlist",
                entry.reviewer_id,
                category.display_name()
            );
        }

        let normalized_logins = entry
            .github_logins
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        by_id.insert(key, normalized_logins);
    }

    Ok(by_id)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedReviewerCategories {
    security: Vec<TrustedReviewer>,
    code_quality: Vec<TrustedReviewer>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedReviewer {
    reviewer_id: String,
    github_logins: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PullRequestResponse {
    head: PullRequestHead,
}

#[derive(Debug, Deserialize)]
struct PullRequestHead {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct CommitStatusResponse {
    statuses: Vec<CommitStatus>,
}

#[derive(Debug, Deserialize)]
struct CommitStatus {
    context: String,
    state: String,
    created_at: String,
}

#[derive(Debug, Clone)]
struct NormalizedStatus {
    context: String,
    state: String,
    created_at: DateTime<Utc>,
}

impl TryFrom<CommitStatus> for NormalizedStatus {
    type Error = anyhow::Error;

    fn try_from(status: CommitStatus) -> Result<Self> {
        let created_at = DateTime::parse_from_rfc3339(&status.created_at)
            .map(|datetime| datetime.with_timezone(&Utc))
            .with_context(|| {
                format!(
                    "Invalid commit status timestamp `{}` for context `{}`",
                    status.created_at, status.context
                )
            })?;

        Ok(Self {
            context: status.context,
            state: status.state,
            created_at,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct IssueComment {
    id: u64,
    body: Option<String>,
    created_at: String,
    updated_at: String,
    user: IssueCommentUser,
}

#[derive(Debug, Clone, Deserialize)]
struct IssueCommentUser {
    login: String,
}

#[derive(Debug)]
struct GateEvaluationInput<'a> {
    pr_number: u64,
    head_sha: &'a str,
    statuses: &'a [NormalizedStatus],
    comments: &'a [IssueComment],
    trusted_reviewers: &'a TrustedReviewerMap,
}

#[derive(Debug, Serialize)]
struct GateEvaluation {
    overall_pass: bool,
    security: CategoryEvaluation,
    code_quality: CategoryEvaluation,
}

#[derive(Debug, Serialize)]
struct CategoryEvaluation {
    pass: bool,
    authoritative_verdict: Option<ReviewVerdict>,
    authoritative_comment_id: Option<u64>,
    status_state: Option<String>,
    reasons: Vec<String>,
}

#[derive(Debug)]
struct CategoryArtifact {
    comment_id: u64,
    updated_at: DateTime<Utc>,
    verdict: Option<ReviewVerdict>,
    rejection_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct GateFixture {
        name: String,
        pr_number: u64,
        head_sha: String,
        statuses: Vec<FixtureStatus>,
        comments: Vec<FixtureComment>,
        expected: FixtureExpected,
    }

    #[derive(Debug, Deserialize)]
    struct FixtureStatus {
        context: String,
        state: String,
        created_at: String,
    }

    #[derive(Debug, Deserialize)]
    struct FixtureComment {
        id: u64,
        user_login: String,
        updated_at: String,
        body: String,
    }

    #[derive(Debug, Deserialize)]
    struct FixtureExpected {
        overall_pass: bool,
        security_pass: bool,
        code_quality_pass: bool,
        #[serde(default)]
        security_reason_substrings: Vec<String>,
        #[serde(default)]
        code_quality_reason_substrings: Vec<String>,
    }

    #[test]
    fn review_gate_fixtures_cover_incident_patterns() {
        let trusted_reviewers = load_trusted_reviewers_for_tests();
        let fixtures = load_fixtures();
        assert!(
            !fixtures.is_empty(),
            "Expected at least one review gate fixture case"
        );

        for fixture in fixtures {
            let statuses = fixture
                .statuses
                .iter()
                .map(|status| NormalizedStatus {
                    context: status.context.clone(),
                    state: status.state.clone(),
                    created_at: DateTime::parse_from_rfc3339(&status.created_at)
                        .unwrap_or_else(|error| {
                            panic!(
                                "Fixture `{}` has invalid status timestamp `{}`: {}",
                                fixture.name, status.created_at, error
                            )
                        })
                        .with_timezone(&Utc),
                })
                .collect::<Vec<_>>();

            let comments = fixture
                .comments
                .iter()
                .map(|comment| IssueComment {
                    id: comment.id,
                    body: Some(comment.body.clone()),
                    created_at: comment.updated_at.clone(),
                    updated_at: comment.updated_at.clone(),
                    user: IssueCommentUser {
                        login: comment.user_login.clone(),
                    },
                })
                .collect::<Vec<_>>();

            let input = GateEvaluationInput {
                pr_number: fixture.pr_number,
                head_sha: &fixture.head_sha,
                statuses: &statuses,
                comments: &comments,
                trusted_reviewers: &trusted_reviewers,
            };
            let evaluation = evaluate_gate(&input);

            assert_eq!(
                evaluation.overall_pass, fixture.expected.overall_pass,
                "Fixture `{}` overall gate mismatch",
                fixture.name
            );
            assert_eq!(
                evaluation.security.pass, fixture.expected.security_pass,
                "Fixture `{}` security gate mismatch",
                fixture.name
            );
            assert_eq!(
                evaluation.code_quality.pass, fixture.expected.code_quality_pass,
                "Fixture `{}` code-quality gate mismatch",
                fixture.name
            );

            for substring in &fixture.expected.security_reason_substrings {
                assert!(
                    evaluation
                        .security
                        .reasons
                        .iter()
                        .any(|reason| reason.contains(substring)),
                    "Fixture `{}` expected security reason containing `{substring}`, got {:?}",
                    fixture.name,
                    evaluation.security.reasons
                );
            }
            for substring in &fixture.expected.code_quality_reason_substrings {
                assert!(
                    evaluation
                        .code_quality
                        .reasons
                        .iter()
                        .any(|reason| reason.contains(substring)),
                    "Fixture `{}` expected code-quality reason containing `{substring}`, got {:?}",
                    fixture.name,
                    evaluation.code_quality.reasons
                );
            }
        }
    }

    #[test]
    fn extract_json_after_marker_rejects_missing_code_fence() {
        let body = "<!-- apm2-review-metadata:v1:security -->\nno json fence";
        let result = extract_json_after_marker(body, SECURITY_METADATA_MARKER, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_owner_repo_supports_https_and_ssh() {
        assert_eq!(
            parse_owner_repo("https://github.com/example/project.git"),
            Some("example/project".to_string())
        );
        assert_eq!(
            parse_owner_repo("git@github.com:example/project.git"),
            Some("example/project".to_string())
        );
    }

    fn load_trusted_reviewers_for_tests() -> TrustedReviewerMap {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(".github/review-gate/trusted-reviewers.json");
        let config = TrustedReviewerConfig::load(&config_path).unwrap_or_else(|error| {
            panic!("Failed to load trusted reviewers test config: {error}")
        });
        config
            .to_allowlist_map()
            .unwrap_or_else(|error| panic!("Invalid trusted reviewers test config: {error}"))
    }

    fn load_fixtures() -> Vec<GateFixture> {
        let fixtures_dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/review_gate");
        let mut paths = fs::read_dir(&fixtures_dir)
            .unwrap_or_else(|error| {
                panic!(
                    "Failed to read fixtures directory {}: {error}",
                    fixtures_dir.display()
                )
            })
            .map(|entry| {
                entry
                    .unwrap_or_else(|error| panic!("Failed to read fixture dir entry: {error}"))
                    .path()
            })
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "yaml")
            })
            .collect::<Vec<_>>();
        paths.sort();

        paths
            .iter()
            .map(|path| {
                let content = fs::read_to_string(path).unwrap_or_else(|error| {
                    panic!("Failed to read fixture {}: {error}", path.display())
                });
                serde_yaml::from_str::<GateFixture>(&content).unwrap_or_else(|error| {
                    panic!("Failed to parse fixture {}: {error}", path.display())
                })
            })
            .collect()
    }
}
