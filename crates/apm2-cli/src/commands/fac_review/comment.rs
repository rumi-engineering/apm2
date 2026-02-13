//! `apm2 fac review comment` — publish one SHA-bound finding comment.

use std::io::{Read, Stdin};
use std::process::Command;

use clap::ValueEnum;
use serde::Serialize;

use super::barrier::{ensure_gh_cli_ready, resolve_authenticated_gh_login};
use super::projection_store;
use super::publish::create_issue_comment;
use super::target::resolve_pr_target;
use super::types::validate_expected_head_sha;
use crate::exit_codes::codes as exit_codes;

const COMMENT_SCHEMA: &str = "apm2.fac.review.comment.v1";
const FINDING_METADATA_SCHEMA: &str = "apm2.finding.v1";
const MAX_STDIN_BODY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReviewCommentSeverityArg {
    Blocker,
    Major,
    Minor,
    Nit,
}

impl ReviewCommentSeverityArg {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocker => "blocker",
            Self::Major => "major",
            Self::Minor => "minor",
            Self::Nit => "nit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReviewCommentTypeArg {
    Security,
    #[value(alias = "quality")]
    CodeQuality,
}

impl ReviewCommentTypeArg {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::CodeQuality => "code-quality",
        }
    }
}

#[derive(Debug, Serialize)]
struct ReviewCommentSummary {
    schema: String,
    repo: String,
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    review_type: String,
    severity: String,
    comment_id: u64,
    comment_url: String,
}

fn resolve_head_sha(sha: Option<&str>) -> Result<String, String> {
    if let Some(value) = sha {
        validate_expected_head_sha(value)?;
        return Ok(value.to_ascii_lowercase());
    }

    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("failed to execute git rev-parse HEAD: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let resolved = String::from_utf8_lossy(&output.stdout).trim().to_string();
    validate_expected_head_sha(&resolved)?;
    Ok(resolved.to_ascii_lowercase())
}

fn read_bounded_stdin_body(stdin: &mut Stdin) -> Result<String, String> {
    let mut body = String::new();
    let mut reader = stdin.take(MAX_STDIN_BODY_BYTES + 1);
    reader
        .read_to_string(&mut body)
        .map_err(|err| format!("failed to read comment body from stdin: {err}"))?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_STDIN_BODY_BYTES {
        return Err(format!(
            "stdin comment body exceeds {MAX_STDIN_BODY_BYTES} bytes"
        ));
    }
    let normalized = body.trim();
    if normalized.is_empty() {
        return Err("comment body is empty; pass --body or pipe non-empty stdin".to_string());
    }
    Ok(body.trim_end().to_string())
}

fn resolve_comment_body(body: Option<&str>) -> Result<String, String> {
    if let Some(value) = body {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err("comment body is empty; pass non-empty --body text".to_string());
        }
        return Ok(value.trim_end().to_string());
    }
    let mut stdin = std::io::stdin();
    read_bounded_stdin_body(&mut stdin)
}

fn render_finding_comment(
    body: &str,
    review_type: ReviewCommentTypeArg,
    severity: ReviewCommentSeverityArg,
    head_sha: &str,
    pr_number: u32,
    reviewer_id: &str,
) -> Result<String, String> {
    validate_expected_head_sha(head_sha)?;
    let short_sha = head_sha.chars().take(8).collect::<String>();
    let marker = format!(
        "<!-- apm2-finding:v1:{}:{}:{} -->",
        review_type.as_str(),
        short_sha,
        severity.as_str()
    );
    let metadata = serde_json::json!({
        "schema": FINDING_METADATA_SCHEMA,
        "review_type": review_type.as_str(),
        "severity": severity.as_str(),
        "head_sha": head_sha,
        "pr_number": pr_number,
        "reviewer_id": reviewer_id,
    });
    let metadata_json = serde_json::to_string_pretty(&metadata)
        .map_err(|err| format!("failed to serialize finding metadata JSON: {err}"))?;
    Ok(format!(
        "{}\n\n{}\n```json\n{}\n```\n",
        body.trim_end(),
        marker,
        metadata_json
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn run_comment(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    severity: ReviewCommentSeverityArg,
    review_type: ReviewCommentTypeArg,
    body: Option<&str>,
    json_output: bool,
) -> Result<u8, String> {
    ensure_gh_cli_ready()?;
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let reviewer_id = resolve_reviewer_id(&owner_repo, resolved_pr)?;
    let head_sha = resolve_head_sha(sha)?;
    let resolved_body = resolve_comment_body(body)?;
    let rendered = render_finding_comment(
        &resolved_body,
        review_type,
        severity,
        &head_sha,
        resolved_pr,
        &reviewer_id,
    )?;
    let response = create_issue_comment(&owner_repo, resolved_pr, &rendered)?;

    let summary = ReviewCommentSummary {
        schema: COMMENT_SCHEMA.to_string(),
        repo: owner_repo.clone(),
        pr_number: resolved_pr,
        pr_url: format!("https://github.com/{owner_repo}/pull/{resolved_pr}"),
        head_sha,
        review_type: review_type.as_str().to_string(),
        severity: severity.as_str().to_string(),
        comment_id: response.id,
        comment_url: response.html_url,
    };
    let _ = projection_store::save_trusted_reviewer_id(&owner_repo, resolved_pr, &reviewer_id);
    let _ = projection_store::save_identity_with_context(
        &owner_repo,
        resolved_pr,
        &summary.head_sha,
        "comment",
    );
    let _ = projection_store::upsert_issue_comment_cache_entry(
        &owner_repo,
        resolved_pr,
        summary.comment_id,
        &summary.comment_url,
        &rendered,
        &reviewer_id,
    );

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("FAC Review Comment");
        println!("  Repo:         {}", summary.repo);
        println!("  PR Number:    {}", summary.pr_number);
        println!("  PR URL:       {}", summary.pr_url);
        println!("  Head SHA:     {}", summary.head_sha);
        println!("  Review Type:  {}", summary.review_type);
        println!("  Severity:     {}", summary.severity);
        println!("  Comment ID:   {}", summary.comment_id);
        println!("  Comment URL:  {}", summary.comment_url);
    }

    Ok(exit_codes::SUCCESS)
}

fn resolve_reviewer_id(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    if let Some(cached) = projection_store::load_trusted_reviewer_id(owner_repo, pr_number)? {
        return Ok(cached);
    }

    if !projection_store::gh_read_fallback_enabled() {
        return Err(projection_store::gh_read_fallback_disabled_error(
            "comment.resolve_reviewer_id",
        ));
    }

    let reviewer_id = resolve_authenticated_gh_login()
        .ok_or_else(|| "failed to resolve authenticated GitHub login".to_string())?;
    let _ = projection_store::record_fallback_read(
        owner_repo,
        pr_number,
        "comment.resolve_reviewer_id",
    );
    let _ = projection_store::save_trusted_reviewer_id(owner_repo, pr_number, &reviewer_id);
    Ok(reviewer_id)
}

#[cfg(test)]
mod tests {
    use super::{
        ReviewCommentSeverityArg, ReviewCommentTypeArg, render_finding_comment, resolve_head_sha,
    };

    #[test]
    fn render_finding_comment_appends_marker_and_metadata() {
        let rendered = render_finding_comment(
            "Unsafe `Command` invocation without input validation.",
            ReviewCommentTypeArg::Security,
            ReviewCommentSeverityArg::Major,
            "0123456789abcdef0123456789abcdef01234567",
            503,
            "fac-bot",
        )
        .expect("rendered");
        assert!(rendered.contains("<!-- apm2-finding:v1:security:01234567:major -->"));
        assert!(rendered.contains("\"schema\": \"apm2.finding.v1\""));
        assert!(rendered.contains("\"review_type\": \"security\""));
        assert!(rendered.contains("\"severity\": \"major\""));
        assert!(rendered.contains("\"pr_number\": 503"));
    }

    #[test]
    fn resolve_head_sha_accepts_explicit_override() {
        let sha = resolve_head_sha(Some("abcdefabcdefabcdefabcdefabcdefabcdefabcd")).expect("sha");
        assert_eq!(sha, "abcdefabcdefabcdefabcdefabcdefabcdefabcd");
    }
}
