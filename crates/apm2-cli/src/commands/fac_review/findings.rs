//! FAC-native review findings retrieval from GitHub projection comments.

use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::barrier::{ensure_gh_cli_ready, fetch_pr_head_sha, resolve_authenticated_gh_login};
use super::selector::render_finding_selector;
use super::target::resolve_pr_target;
use super::types::{COMMENT_CONFIRM_MAX_PAGES, validate_expected_head_sha};
use crate::exit_codes::codes as exit_codes;

const FINDINGS_SCHEMA: &str = "apm2.fac.review.findings.v1";

const SECURITY_DIMENSION: &str = "security";
const CODE_QUALITY_DIMENSION: &str = "code-quality";

const SECURITY_MARKER: &str = "<!-- apm2-review-metadata:v1:security -->";
const QUALITY_MARKER: &str = "<!-- apm2-review-metadata:v1:code-quality -->";

#[derive(Debug, Clone, Serialize)]
struct FindingsReport {
    schema: String,
    pr_number: u32,
    head_sha: String,
    overall_status: String,
    fail_closed: bool,
    dimensions: Vec<DimensionFindings>,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DimensionFindings {
    dimension: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_comment_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_comment_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity_counts: Option<SeverityCounts>,
    findings: Vec<FindingRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FindingRecord {
    severity: String,
    reviewer_type: String,
    sha: String,
    summary: String,
    evidence_selector: String,
    evidence_digest: String,
    raw_evidence_pointer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeverityCounts {
    blocker: u64,
    major: u64,
    minor: u64,
    nit: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ReviewMetadata {
    schema: String,
    review_type: String,
    pr_number: u32,
    head_sha: String,
    verdict: String,
    severity_counts: SeverityCounts,
}

#[derive(Debug, Clone, Deserialize)]
struct IssueComment {
    id: u64,
    body: String,
    html_url: String,
    created_at: String,
    #[serde(default)]
    user: Option<IssueUser>,
}

#[derive(Debug, Clone, Deserialize)]
struct IssueUser {
    login: String,
}

#[derive(Debug, Clone)]
struct ParsedReviewComment {
    comment: IssueComment,
    metadata: ReviewMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionSeverity {
    Blocker,
    Major,
    Minor,
    Nit,
}

impl SectionSeverity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Blocker => "BLOCKER",
            Self::Major => "MAJOR",
            Self::Minor => "MINOR",
            Self::Nit => "NIT",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DimensionSpec {
    dimension: &'static str,
    marker: &'static str,
}

const DIMENSIONS: [DimensionSpec; 2] = [
    DimensionSpec {
        dimension: SECURITY_DIMENSION,
        marker: SECURITY_MARKER,
    },
    DimensionSpec {
        dimension: CODE_QUALITY_DIMENSION,
        marker: QUALITY_MARKER,
    },
];

pub fn run_findings(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    json_output: bool,
) -> Result<u8, String> {
    ensure_gh_cli_ready()?;
    let expected_author_login = resolve_authenticated_gh_login().ok_or_else(|| {
        "failed to resolve authenticated GitHub login for trusted projection comment filtering"
            .to_string()
    })?;
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number, pr_url)?;
    let resolved_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;
    let comments = fetch_issue_comments(&owner_repo, resolved_pr)?;
    let report = build_findings_report(
        &owner_repo,
        resolved_pr,
        &resolved_sha,
        &comments,
        &expected_author_login,
    );
    emit_report(&report, json_output)?;

    if report.fail_closed {
        Ok(exit_codes::GENERIC_ERROR)
    } else {
        Ok(exit_codes::SUCCESS)
    }
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

fn fetch_issue_comments(owner_repo: &str, pr_number: u32) -> Result<Vec<IssueComment>, String> {
    let mut collected = Vec::new();
    for page in 1..=COMMENT_CONFIRM_MAX_PAGES {
        let endpoint =
            format!("/repos/{owner_repo}/issues/{pr_number}/comments?per_page=100&page={page}");
        let output = Command::new("gh")
            .args(["api", &endpoint])
            .output()
            .map_err(|err| format!("failed to execute gh api for comments: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "gh api failed fetching comments: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let page_comments: Vec<IssueComment> = serde_json::from_slice(&output.stdout)
            .map_err(|err| format!("failed to parse comments response: {err}"))?;
        if page_comments.is_empty() {
            break;
        }
        collected.extend(page_comments);
    }
    Ok(collected)
}

fn build_findings_report(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    comments: &[IssueComment],
    expected_author_login: &str,
) -> FindingsReport {
    let mut dimensions = Vec::with_capacity(DIMENSIONS.len());
    let mut errors = Vec::new();
    let mut fail_closed = false;

    for spec in DIMENSIONS {
        let dimension = evaluate_dimension(
            spec,
            owner_repo,
            pr_number,
            head_sha,
            comments,
            expected_author_login,
        );
        let status_fail_closed = matches!(
            dimension.status.as_str(),
            "ERROR" | "MISSING" | "STALE" | "AMBIGUOUS"
        );
        if status_fail_closed {
            fail_closed = true;
        }
        if let Some(error) = &dimension.error {
            errors.push(format!("{}: {error}", dimension.dimension));
        }
        dimensions.push(dimension);
    }

    let overall_status = if fail_closed {
        "ERROR".to_string()
    } else if dimensions.iter().any(|d| d.status == "FAIL") {
        "FAIL".to_string()
    } else {
        "PASS".to_string()
    };

    FindingsReport {
        schema: FINDINGS_SCHEMA.to_string(),
        pr_number,
        head_sha: head_sha.to_string(),
        overall_status,
        fail_closed,
        dimensions,
        errors,
    }
}

fn evaluate_dimension(
    spec: DimensionSpec,
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    comments: &[IssueComment],
    expected_author_login: &str,
) -> DimensionFindings {
    let marker_count = comments
        .iter()
        .filter(|comment| comment.body.contains(spec.marker))
        .count();
    let marker_comments = comments
        .iter()
        .filter(|comment| {
            comment.body.contains(spec.marker)
                && comment_user_login(comment)
                    .is_some_and(|author| author.eq_ignore_ascii_case(expected_author_login))
        })
        .cloned()
        .collect::<Vec<_>>();

    if marker_comments.is_empty() {
        return DimensionFindings {
            dimension: spec.dimension.to_string(),
            status: "MISSING".to_string(),
            source_comment_id: None,
            source_comment_url: None,
            verdict: None,
            severity_counts: None,
            findings: Vec::new(),
            error: Some(if marker_count == 0 {
                "no marker comment found".to_string()
            } else {
                format!(
                    "marker comments exist but none were authored by trusted login `{expected_author_login}`"
                )
            }),
        };
    }

    let mut parse_errors = Vec::new();
    let mut parsed = Vec::new();
    for comment in marker_comments {
        match parse_review_comment(spec, pr_number, &comment) {
            Ok(value) => parsed.push(value),
            Err(err) => parse_errors.push(format!("comment {}: {err}", comment.id)),
        }
    }

    if parsed.is_empty() {
        return DimensionFindings {
            dimension: spec.dimension.to_string(),
            status: "ERROR".to_string(),
            source_comment_id: None,
            source_comment_url: None,
            verdict: None,
            severity_counts: None,
            findings: Vec::new(),
            error: Some(format!(
                "all marker comments were invalid ({})",
                parse_errors.join("; ")
            )),
        };
    }

    let mut matching_sha = parsed
        .iter()
        .filter(|entry| entry.metadata.head_sha.eq_ignore_ascii_case(head_sha))
        .cloned()
        .collect::<Vec<_>>();
    if matching_sha.is_empty() {
        return DimensionFindings {
            dimension: spec.dimension.to_string(),
            status: "STALE".to_string(),
            source_comment_id: None,
            source_comment_url: None,
            verdict: None,
            severity_counts: None,
            findings: Vec::new(),
            error: Some(format!("no marker comment for head sha {head_sha}")),
        };
    }

    matching_sha.sort_by(|a, b| {
        (&a.comment.created_at, a.comment.id).cmp(&(&b.comment.created_at, b.comment.id))
    });

    let has_conflicting_verdicts = matching_sha
        .iter()
        .map(|entry| entry.metadata.verdict.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        > 1;
    if has_conflicting_verdicts {
        return DimensionFindings {
            dimension: spec.dimension.to_string(),
            status: "AMBIGUOUS".to_string(),
            source_comment_id: None,
            source_comment_url: None,
            verdict: None,
            severity_counts: None,
            findings: Vec::new(),
            error: Some("multiple matching comments disagree on verdict".to_string()),
        };
    }

    let Some(selected) = matching_sha.pop() else {
        return DimensionFindings {
            dimension: spec.dimension.to_string(),
            status: "ERROR".to_string(),
            source_comment_id: None,
            source_comment_url: None,
            verdict: None,
            severity_counts: None,
            findings: Vec::new(),
            error: Some("internal selection error".to_string()),
        };
    };

    let findings = match parse_findings_from_comment(
        &selected.comment.body,
        owner_repo,
        pr_number,
        selected.comment.id,
        head_sha,
        spec.dimension,
        &selected.comment.html_url,
    ) {
        Ok(items) => items,
        Err(err) => {
            return DimensionFindings {
                dimension: spec.dimension.to_string(),
                status: "ERROR".to_string(),
                source_comment_id: Some(selected.comment.id),
                source_comment_url: Some(selected.comment.html_url),
                verdict: Some(selected.metadata.verdict),
                severity_counts: Some(selected.metadata.severity_counts),
                findings: Vec::new(),
                error: Some(err),
            };
        },
    };

    let expected_findings = selected.metadata.severity_counts.blocker
        + selected.metadata.severity_counts.major
        + selected.metadata.severity_counts.minor
        + selected.metadata.severity_counts.nit;
    if expected_findings > 0 && findings.is_empty() {
        return DimensionFindings {
            dimension: spec.dimension.to_string(),
            status: "ERROR".to_string(),
            source_comment_id: Some(selected.comment.id),
            source_comment_url: Some(selected.comment.html_url),
            verdict: Some(selected.metadata.verdict),
            severity_counts: Some(selected.metadata.severity_counts),
            findings: Vec::new(),
            error: Some(
                "metadata reports findings but comment body had no parseable finding items"
                    .to_string(),
            ),
        };
    }

    DimensionFindings {
        dimension: spec.dimension.to_string(),
        status: selected.metadata.verdict.clone(),
        source_comment_id: Some(selected.comment.id),
        source_comment_url: Some(selected.comment.html_url),
        verdict: Some(selected.metadata.verdict),
        severity_counts: Some(selected.metadata.severity_counts),
        findings,
        error: None,
    }
}

fn comment_user_login(comment: &IssueComment) -> Option<&str> {
    comment.user.as_ref().map(|value| value.login.as_str())
}

fn parse_review_comment(
    spec: DimensionSpec,
    pr_number: u32,
    comment: &IssueComment,
) -> Result<ParsedReviewComment, String> {
    let metadata = parse_metadata_from_comment(&comment.body, spec.marker)?;
    if metadata.schema != "apm2.review.metadata.v1" {
        return Err(format!("invalid metadata schema `{}`", metadata.schema));
    }
    if metadata.pr_number != pr_number {
        return Err(format!(
            "metadata pr_number={} does not match target pr_number={pr_number}",
            metadata.pr_number
        ));
    }
    validate_expected_head_sha(&metadata.head_sha)?;
    let normalized_type = normalize_review_type(&metadata.review_type);
    if normalized_type != spec.dimension {
        return Err(format!(
            "metadata review_type `{}` does not match marker dimension `{}`",
            metadata.review_type, spec.dimension
        ));
    }
    if !matches!(metadata.verdict.as_str(), "PASS" | "FAIL") {
        return Err(format!(
            "invalid metadata verdict `{}` (expected PASS|FAIL)",
            metadata.verdict
        ));
    }

    Ok(ParsedReviewComment {
        comment: comment.clone(),
        metadata,
    })
}

fn normalize_review_type(input: &str) -> String {
    match input.trim().to_ascii_lowercase().as_str() {
        "security" => SECURITY_DIMENSION.to_string(),
        "quality" | "code-quality" | "code_quality" => CODE_QUALITY_DIMENSION.to_string(),
        other => other.to_string(),
    }
}

fn parse_metadata_from_comment(body: &str, marker: &str) -> Result<ReviewMetadata, String> {
    let marker_idx = body
        .find(marker)
        .ok_or_else(|| "marker not found in comment body".to_string())?;
    let after_marker = &body[marker_idx + marker.len()..];
    let json_payload = extract_fenced_block(after_marker, "json")
        .ok_or_else(|| "missing fenced json metadata block after marker".to_string())?;
    serde_json::from_str::<ReviewMetadata>(json_payload)
        .map_err(|err| format!("failed to parse metadata JSON: {err}"))
}

fn extract_fenced_block<'a>(source: &'a str, language: &str) -> Option<&'a str> {
    let start_marker = format!("```{language}");
    let start = source.find(&start_marker)?;
    let after_start = &source[start + start_marker.len()..];
    let content = after_start.strip_prefix('\n').unwrap_or(after_start);
    let end = content.find("\n```")?;
    Some(content[..end].trim())
}

fn parse_findings_from_comment(
    body: &str,
    owner_repo: &str,
    pr_number: u32,
    comment_id: u64,
    head_sha: &str,
    reviewer_type: &str,
    comment_url: &str,
) -> Result<Vec<FindingRecord>, String> {
    let mut findings = Vec::new();
    let mut current_severity = None;
    let evidence_digest = sha256_hex(body.as_bytes());

    for (line_idx, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("<!--") || trimmed.starts_with("```") {
            continue;
        }

        if is_heading(trimmed) {
            current_severity = resolve_heading(trimmed)?;
            continue;
        }

        let Some(severity) = current_severity else {
            continue;
        };

        let summary = parse_finding_summary(trimmed);
        if let Some(text) = summary {
            findings.push(FindingRecord {
                severity: severity.as_str().to_string(),
                reviewer_type: reviewer_type.to_string(),
                sha: head_sha.to_string(),
                summary: text.to_string(),
                evidence_selector: render_finding_selector(
                    owner_repo,
                    pr_number,
                    head_sha,
                    reviewer_type,
                    comment_id,
                    line_idx + 1,
                ),
                evidence_digest: evidence_digest.clone(),
                raw_evidence_pointer: format!("{comment_url}#line-{}", line_idx + 1),
            });
        }
    }

    Ok(findings)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn is_heading(line: &str) -> bool {
    line.starts_with('#')
}

fn resolve_heading(line: &str) -> Result<Option<SectionSeverity>, String> {
    let upper = line.to_ascii_uppercase();
    if upper.contains("BLOCKER FINDINGS") {
        return Ok(Some(SectionSeverity::Blocker));
    }
    if upper.contains("MAJOR FINDINGS") {
        return Ok(Some(SectionSeverity::Major));
    }
    if upper.contains("MINOR FINDINGS") {
        return Ok(Some(SectionSeverity::Minor));
    }
    if upper.contains("NITS") || upper.contains("NIT FINDINGS") {
        return Ok(Some(SectionSeverity::Nit));
    }
    if upper.contains("WAIVED FINDINGS")
        || upper.contains("POSITIVE OBSERVATIONS")
        || upper.contains("ASSURANCE CASE")
    {
        return Ok(None);
    }
    if upper.contains("FINDINGS") {
        return Err(format!("unknown findings heading `{line}`"));
    }
    Ok(None)
}

fn parse_finding_summary(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("- ") {
        return Some(rest.trim());
    }
    if let Some(rest) = line.strip_prefix("* ") {
        return Some(rest.trim());
    }
    if let Some(rest) = line.strip_prefix("Issue:") {
        return Some(rest.trim());
    }
    let mut chars = line.chars();
    let mut digit_count = 0usize;
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() {
            digit_count += 1;
            continue;
        }
        if ch == '.' && digit_count > 0 {
            let remainder = chars.as_str().trim_start();
            if !remainder.is_empty() {
                return Some(remainder);
            }
        }
        break;
    }
    None
}

fn emit_report(report: &FindingsReport, json_output: bool) -> Result<(), String> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(report)
                .map_err(|err| format!("failed to serialize findings report: {err}"))?
        );
        return Ok(());
    }

    println!("FAC Review Findings");
    println!("  PR:            #{}", report.pr_number);
    println!("  Head SHA:      {}", report.head_sha);
    println!("  Overall:       {}", report.overall_status);
    for dimension in &report.dimensions {
        println!("  - {}: {}", dimension.dimension, dimension.status);
        if let Some(url) = &dimension.source_comment_url {
            println!("      source: {url}");
        }
        if let Some(error) = &dimension.error {
            println!("      error:  {error}");
        } else {
            println!("      findings: {}", dimension.findings.len());
        }
    }
    if !report.errors.is_empty() {
        println!("  Errors:");
        for error in &report.errors {
            println!("    - {error}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CODE_QUALITY_DIMENSION, DimensionSpec, IssueComment, IssueUser, SECURITY_DIMENSION,
        SECURITY_MARKER, SeverityCounts, evaluate_dimension, normalize_review_type,
        parse_findings_from_comment, parse_metadata_from_comment,
    };

    #[test]
    fn test_parse_metadata_block_success() {
        let body = r#"
## Security Review: PASS

<!-- apm2-review-metadata:v1:security -->
```json
{
  "schema": "apm2.review.metadata.v1",
  "review_type": "security",
  "pr_number": 441,
  "head_sha": "0123456789abcdef0123456789abcdef01234567",
  "verdict": "PASS",
  "severity_counts": {
    "blocker": 0,
    "major": 0,
    "minor": 1,
    "nit": 2
  }
}
```
"#;
        let metadata = parse_metadata_from_comment(body, SECURITY_MARKER).expect("metadata");
        assert_eq!(metadata.review_type, "security");
        assert_eq!(
            metadata.head_sha,
            "0123456789abcdef0123456789abcdef01234567"
        );
    }

    #[test]
    fn test_parse_findings_sections_extracts_expected_items() {
        let body = r"
### **BLOCKER FINDINGS**
1. Issue: unsafe temporary path creation can race with attacker symlink.

### **MAJOR FINDINGS**
- Missing regression test for failed auth branch.

### **MINOR FINDINGS**
* Improve error context when command resolution fails.

### **NITS**
1. Rename local variable for readability.
";
        let findings = parse_findings_from_comment(
            body,
            "guardian-intelligence/apm2",
            482,
            123_456,
            "0123456789abcdef0123456789abcdef01234567",
            CODE_QUALITY_DIMENSION,
            "https://example.invalid/comment/1",
        )
        .expect("findings");
        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0].severity, "BLOCKER");
        assert_eq!(findings[1].severity, "MAJOR");
        assert_eq!(findings[2].severity, "MINOR");
        assert_eq!(findings[3].severity, "NIT");
        assert_eq!(
            findings[0].evidence_selector,
            "finding:v1:guardian-intelligence/apm2:482:0123456789abcdef0123456789abcdef01234567:code-quality:123456:3"
        );
        assert_eq!(findings[0].evidence_digest.len(), 64);
    }

    #[test]
    fn test_parse_findings_sections_rejects_unknown_heading() {
        let body = r"
### **CRITICAL FINDINGS**
1. Something bad.
";
        let err = parse_findings_from_comment(
            body,
            "guardian-intelligence/apm2",
            482,
            123_456,
            "0123456789abcdef0123456789abcdef01234567",
            CODE_QUALITY_DIMENSION,
            "https://example.invalid/comment/1",
        )
        .expect_err("should fail on unknown heading");
        assert!(err.contains("unknown findings heading"));
    }

    #[test]
    fn test_normalize_review_type_quality_alias() {
        assert_eq!(normalize_review_type("quality"), CODE_QUALITY_DIMENSION);
        assert_eq!(
            normalize_review_type("code_quality"),
            CODE_QUALITY_DIMENSION
        );
    }

    #[test]
    fn test_severity_counts_deserialize() {
        let json = r#"{"blocker":1,"major":2,"minor":3,"nit":4}"#;
        let parsed: SeverityCounts =
            serde_json::from_str(json).expect("severity counts should deserialize");
        assert_eq!(parsed.blocker, 1);
        assert_eq!(parsed.major, 2);
        assert_eq!(parsed.minor, 3);
        assert_eq!(parsed.nit, 4);
    }

    #[test]
    fn test_evaluate_dimension_rejects_untrusted_marker_comments() {
        let body = r#"
<!-- apm2-review-metadata:v1:security -->
```json
{
  "schema": "apm2.review.metadata.v1",
  "review_type": "security",
  "pr_number": 441,
  "head_sha": "0123456789abcdef0123456789abcdef01234567",
  "verdict": "PASS",
  "severity_counts": {
    "blocker": 0,
    "major": 0,
    "minor": 0,
    "nit": 0
  }
}
```
"#;
        let comments = vec![IssueComment {
            id: 1,
            body: body.to_string(),
            html_url: "https://example.invalid/comment/1".to_string(),
            created_at: "2026-02-11T00:00:00Z".to_string(),
            user: Some(IssueUser {
                login: "untrusted-user".to_string(),
            }),
        }];

        let dimension = evaluate_dimension(
            DimensionSpec {
                dimension: SECURITY_DIMENSION,
                marker: SECURITY_MARKER,
            },
            "guardian-intelligence/apm2",
            441,
            "0123456789abcdef0123456789abcdef01234567",
            &comments,
            "fac-bot",
        );

        assert_eq!(dimension.status, "MISSING");
        assert!(
            dimension
                .error
                .as_deref()
                .is_some_and(|err| err.contains("trusted login `fac-bot`"))
        );
    }
}
