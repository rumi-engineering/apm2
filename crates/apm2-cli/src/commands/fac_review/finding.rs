//! `apm2 fac review finding` - append one SHA-bound finding to local FAC truth.

use std::io::{Read, Stdin};

use clap::ValueEnum;
use serde::Serialize;

use super::findings::render_finding_selector;
use super::state::resolve_local_review_head_sha;
use super::target::resolve_pr_target;
use super::types::validate_expected_head_sha;
use super::{findings_store, projection_store};
use crate::exit_codes::codes as exit_codes;

const FINDING_SCHEMA: &str = "apm2.fac.review.finding.v1";
const COMMENT_COMPAT_SOURCE: &str = "review.comment.compat";
const FINDING_SOURCE: &str = "review.finding";
const MAX_STDIN_BODY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReviewFindingSeverityArg {
    Blocker,
    Major,
    Minor,
    Nit,
}

impl ReviewFindingSeverityArg {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocker => "BLOCKER",
            Self::Major => "MAJOR",
            Self::Minor => "MINOR",
            Self::Nit => "NIT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReviewFindingTypeArg {
    Security,
    #[value(alias = "quality")]
    CodeQuality,
}

impl ReviewFindingTypeArg {
    pub const fn as_dimension(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::CodeQuality => "code-quality",
        }
    }
}

#[derive(Debug, Serialize)]
struct FindingSummary {
    schema: String,
    repo: String,
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    review_type: String,
    severity: String,
    finding_id: String,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reviewer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend_id: Option<String>,
    created_at: String,
    evidence_selector: String,
    evidence_digest: String,
    raw_evidence_pointer: String,
}

fn resolve_head_sha(owner_repo: &str, pr_number: u32, sha: Option<&str>) -> Result<String, String> {
    if let Some(value) = sha {
        validate_expected_head_sha(value)?;
        return Ok(value.to_ascii_lowercase());
    }

    if let Some(identity) = projection_store::load_pr_identity(owner_repo, pr_number)? {
        validate_expected_head_sha(&identity.head_sha)?;
        return Ok(identity.head_sha.to_ascii_lowercase());
    }

    if let Some(value) = resolve_local_review_head_sha(pr_number) {
        return Ok(value);
    }

    Err(format!(
        "missing local head SHA for PR #{pr_number}; pass --sha explicitly or run local FAC push/review first"
    ))
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
}

#[allow(clippy::too_many_arguments)]
fn run_finding_inner(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    review_type: ReviewFindingTypeArg,
    severity: ReviewFindingSeverityArg,
    summary: &str,
    details: Option<&str>,
    risk: Option<&str>,
    impact: Option<&str>,
    location: Option<&str>,
    reviewer_id: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    evidence_pointer: Option<&str>,
    source: &str,
    json_output: bool,
) -> Result<u8, String> {
    let normalized_summary = summary.trim();
    if normalized_summary.is_empty() {
        return Err("finding summary is empty".to_string());
    }
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let head_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;
    let dimension = review_type.as_dimension();

    let (_, finding) = findings_store::append_dimension_finding(
        &owner_repo,
        resolved_pr,
        &head_sha,
        dimension,
        severity.as_str(),
        normalized_summary,
        details,
        risk,
        impact,
        location,
        reviewer_id,
        model_id,
        backend_id,
        evidence_pointer,
        source,
    )?;

    let selector = render_finding_selector(
        &owner_repo,
        resolved_pr,
        &head_sha,
        dimension,
        &finding.finding_id,
    );
    let summary = FindingSummary {
        schema: FINDING_SCHEMA.to_string(),
        repo: owner_repo.clone(),
        pr_number: resolved_pr,
        pr_url: format!("https://github.com/{owner_repo}/pull/{resolved_pr}"),
        head_sha,
        review_type: dimension.to_string(),
        severity: finding.severity.clone(),
        finding_id: finding.finding_id.clone(),
        summary: finding.summary.clone(),
        details: normalize_optional(finding.details.as_deref()),
        risk: normalize_optional(finding.risk.as_deref()),
        impact: normalize_optional(finding.impact.as_deref()),
        location: normalize_optional(finding.location.as_deref()),
        reviewer_id: normalize_optional(finding.reviewer_id.as_deref()),
        model_id: normalize_optional(finding.model_id.as_deref()),
        backend_id: normalize_optional(finding.backend_id.as_deref()),
        created_at: finding.created_at.clone(),
        evidence_selector: selector,
        evidence_digest: finding.evidence_digest.clone(),
        raw_evidence_pointer: finding.raw_evidence_pointer,
    };

    // Do not retarget authoritative PR identity when appending findings.
    // Findings can arrive from delayed reviewer runs bound to an older SHA.
    // Identity progression is owned by push/restart/dispatch refresh paths.
    let _ = json_output;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(exit_codes::SUCCESS)
}

#[allow(clippy::too_many_arguments)]
pub fn run_finding(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    review_type: ReviewFindingTypeArg,
    severity: ReviewFindingSeverityArg,
    summary: &str,
    details: Option<&str>,
    risk: Option<&str>,
    impact: Option<&str>,
    location: Option<&str>,
    reviewer_id: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    evidence_pointer: Option<&str>,
    json_output: bool,
) -> Result<u8, String> {
    run_finding_inner(
        repo,
        pr_number,
        sha,
        review_type,
        severity,
        summary,
        details,
        risk,
        impact,
        location,
        reviewer_id,
        model_id,
        backend_id,
        evidence_pointer,
        FINDING_SOURCE,
        json_output,
    )
}

fn read_bounded_stdin_body(stdin: &mut Stdin) -> Result<String, String> {
    let mut body = String::new();
    let mut reader = stdin.take(MAX_STDIN_BODY_BYTES + 1);
    reader
        .read_to_string(&mut body)
        .map_err(|err| format!("failed to read comment body from stdin: {err}"))?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_STDIN_BODY_BYTES {
        return Err(format!(
            "stdin body exceeds {MAX_STDIN_BODY_BYTES} bytes for `apm2 fac review comment`"
        ));
    }
    let normalized = body.trim();
    if normalized.is_empty() {
        return Err("comment body is empty; pass --body or pipe non-empty stdin".to_string());
    }
    Ok(normalized.to_string())
}

fn resolve_comment_body(body: Option<&str>) -> Result<String, String> {
    if let Some(value) = body {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err("comment body is empty; pass non-empty --body text".to_string());
        }
        return Ok(normalized.to_string());
    }
    let mut stdin = std::io::stdin();
    read_bounded_stdin_body(&mut stdin)
}

pub fn run_comment_compat(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    review_type: ReviewFindingTypeArg,
    severity: ReviewFindingSeverityArg,
    body: Option<&str>,
    json_output: bool,
) -> Result<u8, String> {
    let summary = resolve_comment_body(body)?;
    run_finding_inner(
        repo,
        pr_number,
        sha,
        review_type,
        severity,
        &summary,
        Some(&summary),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        COMMENT_COMPAT_SOURCE,
        json_output,
    )
}
