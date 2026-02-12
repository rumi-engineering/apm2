//! `apm2 fac review publish` — publish review comments with generated metadata.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use super::barrier::{
    ensure_gh_cli_ready, fetch_pr_head_sha, render_comment_with_generated_metadata,
    resolve_authenticated_gh_login,
};
use super::target::resolve_pr_target;
use super::types::{QUALITY_MARKER, SECURITY_MARKER, validate_expected_head_sha};
use crate::exit_codes::codes as exit_codes;

const PUBLISH_SCHEMA: &str = "apm2.fac.review.publish.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReviewPublishTypeArg {
    Security,
    #[value(alias = "quality")]
    CodeQuality,
}

impl ReviewPublishTypeArg {
    const fn metadata_spec(self) -> (&'static str, &'static str) {
        match self {
            Self::Security => (SECURITY_MARKER, "security"),
            Self::CodeQuality => (QUALITY_MARKER, "code-quality"),
        }
    }
}

#[derive(Debug, Serialize)]
struct PublishSummary {
    schema: String,
    repo: String,
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    review_type: String,
    body_file: String,
    comment_id: u64,
    comment_url: String,
}

#[derive(Debug, Deserialize)]
struct IssueCommentResponse {
    id: u64,
    html_url: String,
}

pub fn run_publish(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    review_type: ReviewPublishTypeArg,
    body_file: &Path,
    json_output: bool,
) -> Result<u8, String> {
    ensure_gh_cli_ready()?;
    let reviewer_id = resolve_authenticated_gh_login().ok_or_else(|| {
        "failed to resolve authenticated GitHub login for metadata reviewer_id".to_string()
    })?;
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number, pr_url)?;
    let head_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;

    let raw_body = std::fs::read_to_string(body_file)
        .map_err(|err| format!("failed to read body file {}: {err}", body_file.display()))?;
    let (marker, review_type_label) = review_type.metadata_spec();
    let enriched_body = render_comment_with_generated_metadata(
        &raw_body,
        marker,
        review_type_label,
        resolved_pr,
        &head_sha,
        &reviewer_id,
    )?;
    let response = create_issue_comment(&owner_repo, resolved_pr, &enriched_body)?;

    let summary = PublishSummary {
        schema: PUBLISH_SCHEMA.to_string(),
        repo: owner_repo.clone(),
        pr_number: resolved_pr,
        pr_url: format!("https://github.com/{owner_repo}/pull/{resolved_pr}"),
        head_sha,
        review_type: review_type_label.to_string(),
        body_file: body_file.display().to_string(),
        comment_id: response.id,
        comment_url: response.html_url,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("FAC Review Publish");
        println!("  Repo:         {}", summary.repo);
        println!("  PR Number:    {}", summary.pr_number);
        println!("  PR URL:       {}", summary.pr_url);
        println!("  Head SHA:     {}", summary.head_sha);
        println!("  Review Type:  {}", summary.review_type);
        println!("  Body File:    {}", summary.body_file);
        println!("  Comment ID:   {}", summary.comment_id);
        println!("  Comment URL:  {}", summary.comment_url);
    }

    Ok(exit_codes::SUCCESS)
}

fn resolve_head_sha(owner_repo: &str, pr_number: u32, sha: Option<&str>) -> Result<String, String> {
    if let Some(value) = sha {
        validate_expected_head_sha(value)?;
        return Ok(value.to_ascii_lowercase());
    }
    let value = fetch_pr_head_sha(owner_repo, pr_number)?;
    validate_expected_head_sha(&value)?;
    Ok(value.to_ascii_lowercase())
}

fn create_issue_comment(
    owner_repo: &str,
    pr_number: u32,
    body: &str,
) -> Result<IssueCommentResponse, String> {
    let mut payload_file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("failed to create temp payload for publish comment: {err}"))?;
    let payload = serde_json::json!({ "body": body });
    let payload_text = serde_json::to_string(&payload)
        .map_err(|err| format!("failed to serialize comment payload: {err}"))?;
    payload_file
        .write_all(payload_text.as_bytes())
        .map_err(|err| format!("failed to write comment payload: {err}"))?;
    payload_file
        .flush()
        .map_err(|err| format!("failed to flush comment payload: {err}"))?;

    let endpoint = format!("/repos/{owner_repo}/issues/{pr_number}/comments");
    let output = Command::new("gh")
        .args([
            "api",
            &endpoint,
            "--method",
            "POST",
            "--input",
            &payload_file.path().display().to_string(),
        ])
        .output()
        .map_err(|err| format!("failed to execute gh api for review publish comment: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed creating review comment: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    serde_json::from_slice::<IssueCommentResponse>(&output.stdout)
        .map_err(|err| format!("failed to parse issue comment response: {err}"))
}

#[cfg(test)]
mod tests {
    use super::ReviewPublishTypeArg;
    use crate::commands::fac_review::barrier::render_comment_with_generated_metadata;

    #[test]
    fn review_publish_type_arg_maps_to_expected_metadata_spec() {
        let (security_marker, security_type) = ReviewPublishTypeArg::Security.metadata_spec();
        assert!(security_marker.contains("security"));
        assert_eq!(security_type, "security");

        let (quality_marker, quality_type) = ReviewPublishTypeArg::CodeQuality.metadata_spec();
        assert!(quality_marker.contains("code-quality"));
        assert_eq!(quality_type, "code-quality");
    }

    #[test]
    fn publish_metadata_generation_appends_machine_readable_block() {
        let body = r"
## Security Review: FAIL

### **BLOCKER FINDINGS**
1. Issue: auth bypass
";
        let rendered = render_comment_with_generated_metadata(
            body,
            "<!-- apm2-review-metadata:v1:security -->",
            "security",
            321,
            "0123456789abcdef0123456789abcdef01234567",
            "fac-reviewer",
        )
        .expect("rendered");

        assert!(rendered.contains("apm2-review-metadata:v1:security"));
        assert!(rendered.contains("\"schema\": \"apm2.review.metadata.v1\""));
        assert!(rendered.contains("\"review_type\": \"security\""));
        assert!(rendered.contains("\"reviewer_id\": \"fac-reviewer\""));
        assert!(rendered.contains("\"verdict\": \"FAIL\""));
        assert!(!rendered.contains("\"severity_counts\""));
    }
}
