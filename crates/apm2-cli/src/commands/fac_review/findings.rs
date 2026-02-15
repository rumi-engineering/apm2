//! FAC-native SHA-bound review findings retrieval.

use serde::Serialize;

use super::findings_store::{self, FindingsBundle, StoredFinding};
use super::state::resolve_local_review_head_sha;
use super::target::resolve_pr_target;
use super::types::{normalize_decision_dimension, split_owner_repo, validate_expected_head_sha};
use super::{projection_store, verdict_projection};
use crate::exit_codes::codes as exit_codes;

const FINDINGS_SCHEMA: &str = "apm2.fac.review.findings.v1";

const SECURITY_DIMENSION: &str = "security";
const CODE_QUALITY_DIMENSION: &str = "code-quality";

// ── Selector tokens ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorType {
    Finding,
    ToolOutput,
}

impl SelectorType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::ToolOutput => "tool_output",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingSelector {
    pub owner_repo: String,
    pub pr: u32,
    pub sha: String,
    pub dimension: String,
    pub finding_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutputSelector {
    pub sha: String,
    pub gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorToken {
    Finding(FindingSelector),
    ToolOutput(ToolOutputSelector),
}

pub fn parse_selector_type(input: &str) -> Result<SelectorType, String> {
    match input.trim().to_ascii_lowercase().as_str() {
        "finding" => Ok(SelectorType::Finding),
        "tool_output" | "tool-output" => Ok(SelectorType::ToolOutput),
        other => Err(format!(
            "invalid selector type `{other}` (expected finding|tool_output)"
        )),
    }
}

pub fn parse_selector(selector_type: SelectorType, token: &str) -> Result<SelectorToken, String> {
    match selector_type {
        SelectorType::Finding => parse_finding_selector(token).map(SelectorToken::Finding),
        SelectorType::ToolOutput => {
            parse_tool_output_selector(token).map(SelectorToken::ToolOutput)
        },
    }
}

#[must_use]
pub fn render_finding_selector(
    owner_repo: &str,
    pr: u32,
    sha: &str,
    dimension: &str,
    finding_id: &str,
) -> String {
    format!(
        "finding:v2:{owner_repo}:{pr}:{sha}:{}:{finding_id}",
        normalize_selector_dimension(dimension)
    )
}

#[must_use]
pub fn render_tool_output_selector(sha: &str, gate: &str) -> String {
    format!("tool_output:v1:{sha}:{gate}")
}

fn normalize_selector_dimension(input: &str) -> String {
    match input.trim().to_ascii_lowercase().as_str() {
        "security" => "security".to_string(),
        "quality" | "code-quality" | "code_quality" => "code-quality".to_string(),
        other => other.to_string(),
    }
}

fn parse_finding_selector(token: &str) -> Result<FindingSelector, String> {
    let parts = token.split(':').collect::<Vec<_>>();
    if parts.len() != 7 {
        return Err(format!(
            "invalid finding selector format `{token}` (expected finding:v2:<owner/repo>:<pr>:<sha>:<dimension>:<finding_id>)"
        ));
    }
    if parts[0] != "finding" || parts[1] != "v2" {
        return Err(format!(
            "invalid finding selector prefix `{token}` (expected finding:v2:...)"
        ));
    }

    let owner_repo = parts[2].trim();
    split_owner_repo(owner_repo)?;
    let pr = parts[3]
        .parse::<u32>()
        .map_err(|err| format!("invalid finding selector pr `{}`: {err}", parts[3]))?;
    if pr == 0 {
        return Err("invalid finding selector pr `0`".to_string());
    }

    let sha = parts[4].to_ascii_lowercase();
    validate_expected_head_sha(&sha)?;
    let dimension = normalize_selector_dimension(parts[5]);
    normalize_decision_dimension(&dimension)?;

    let finding_id = parts[6].trim();
    if finding_id.is_empty() {
        return Err("invalid finding selector finding_id: empty".to_string());
    }
    if finding_id
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
    {
        return Err(format!(
            "invalid finding selector finding_id `{finding_id}`: only [A-Za-z0-9_-] allowed"
        ));
    }

    Ok(FindingSelector {
        owner_repo: owner_repo.to_string(),
        pr,
        sha,
        dimension,
        finding_id: finding_id.to_string(),
    })
}

fn parse_tool_output_selector(token: &str) -> Result<ToolOutputSelector, String> {
    let parts = token.split(':').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(format!(
            "invalid tool output selector format `{token}` (expected tool_output:v1:<sha>:<gate>)"
        ));
    }
    if parts[0] != "tool_output" || parts[1] != "v1" {
        return Err(format!(
            "invalid tool output selector prefix `{token}` (expected tool_output:v1:...)"
        ));
    }
    let sha = parts[2].to_ascii_lowercase();
    validate_expected_head_sha(&sha)?;
    let gate = parts[3].trim().to_string();
    if gate.is_empty() {
        return Err("invalid tool output selector gate: empty".to_string());
    }
    if gate
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
    {
        return Err(format!(
            "invalid tool output selector gate `{gate}`: only [A-Za-z0-9_-] allowed"
        ));
    }
    Ok(ToolOutputSelector { sha, gate })
}

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
    verdict: String,
    findings: Vec<FindingRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FindingRecord {
    finding_id: String,
    severity: String,
    reviewer_type: String,
    sha: String,
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

pub fn run_findings(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    _refresh: bool,
    json_output: bool,
) -> Result<u8, String> {
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let resolved_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;
    let bundle = findings_store::load_findings_bundle(&owner_repo, resolved_pr, &resolved_sha)?;

    let report = build_findings_report(&owner_repo, resolved_pr, &resolved_sha, bundle.as_ref());
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

    if let Some(identity) = projection_store::load_pr_identity(owner_repo, pr_number)? {
        validate_expected_head_sha(&identity.head_sha)?;
        return Ok(identity.head_sha.to_ascii_lowercase());
    }

    if let Some(value) = resolve_local_review_head_sha(pr_number) {
        return Ok(value);
    }

    Err(format!(
        "missing local head SHA for PR #{pr_number}; pass --sha explicitly or run local FAC review first"
    ))
}

fn build_findings_report(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    bundle: Option<&FindingsBundle>,
) -> FindingsReport {
    let mut errors = Vec::new();
    let mut dimensions = Vec::with_capacity(2);

    for dimension in [SECURITY_DIMENSION, CODE_QUALITY_DIMENSION] {
        let view = build_dimension_findings(owner_repo, pr_number, head_sha, dimension, bundle);
        if let Some(error) = &view.error {
            errors.push(format!("{}: {error}", view.dimension));
        }
        dimensions.push(view);
    }

    let fail_closed = dimensions.iter().any(|entry| entry.status == "ERROR");

    let overall_status = if fail_closed {
        "ERROR".to_string()
    } else if dimensions.iter().any(|entry| entry.status == "FAIL") {
        "FAIL".to_string()
    } else if dimensions.iter().all(|entry| entry.status == "PASS") {
        "PASS".to_string()
    } else {
        "PENDING".to_string()
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

fn build_dimension_findings(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
    bundle: Option<&FindingsBundle>,
) -> DimensionFindings {
    let resolved_verdict = match verdict_projection::resolve_verdict_for_dimension(
        owner_repo, pr_number, head_sha, dimension,
    ) {
        Ok(value) => value,
        Err(err) => {
            return DimensionFindings {
                dimension: dimension.to_string(),
                status: "ERROR".to_string(),
                verdict: "pending".to_string(),
                findings: Vec::new(),
                error: Some(format!("failed to resolve verdict: {err}")),
            };
        },
    };

    let mut findings = Vec::new();
    if let Some(bundle) = bundle {
        if bundle.schema != findings_store::FINDINGS_BUNDLE_SCHEMA {
            return DimensionFindings {
                dimension: dimension.to_string(),
                status: "ERROR".to_string(),
                verdict: "pending".to_string(),
                findings: Vec::new(),
                error: Some(format!(
                    "unsupported findings bundle schema `{}`",
                    bundle.schema
                )),
            };
        }
        if let Some(stored_dimension) = findings_store::find_dimension(bundle, dimension) {
            findings = stored_dimension
                .findings
                .iter()
                .map(|entry| to_finding_record(owner_repo, pr_number, head_sha, dimension, entry))
                .collect::<Vec<_>>();
        }
    }

    let (status, verdict) = resolved_verdict.as_deref().map_or_else(
        || ("PENDING".to_string(), "pending".to_string()),
        |value| (value.to_string(), value.to_string()),
    );

    DimensionFindings {
        dimension: dimension.to_string(),
        status,
        verdict,
        findings,
        error: None,
    }
}

fn to_finding_record(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
    finding: &StoredFinding,
) -> FindingRecord {
    let selector = render_finding_selector(
        owner_repo,
        pr_number,
        head_sha,
        dimension,
        &finding.finding_id,
    );

    FindingRecord {
        finding_id: finding.finding_id.clone(),
        severity: normalize_severity(&finding.severity),
        reviewer_type: dimension.to_string(),
        sha: head_sha.to_string(),
        summary: finding.summary.clone(),
        details: finding.details.clone(),
        risk: finding.risk.clone(),
        impact: finding.impact.clone(),
        location: finding.location.clone(),
        reviewer_id: finding.reviewer_id.clone(),
        model_id: finding.model_id.clone(),
        backend_id: finding.backend_id.clone(),
        created_at: finding.created_at.clone(),
        evidence_selector: selector,
        evidence_digest: finding.evidence_digest.clone(),
        raw_evidence_pointer: finding.raw_evidence_pointer.clone(),
    }
}

fn normalize_severity(input: &str) -> String {
    match input.trim().to_ascii_uppercase().as_str() {
        "BLOCKER" => "BLOCKER".to_string(),
        "MAJOR" => "MAJOR".to_string(),
        "MINOR" => "MINOR".to_string(),
        "NIT" => "NIT".to_string(),
        other => other.to_string(),
    }
}

fn emit_report(report: &FindingsReport, json_output: bool) -> Result<(), String> {
    let _ = json_output;
    println!(
        "{}",
        serde_json::to_string_pretty(report)
            .map_err(|err| format!("failed to serialize findings report: {err}"))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CODE_QUALITY_DIMENSION, FindingsBundle, SECURITY_DIMENSION, SelectorToken, SelectorType,
        build_findings_report, parse_selector, parse_selector_type, render_finding_selector,
        render_tool_output_selector,
    };
    use crate::commands::fac_review::findings_store::{StoredDimensionFindings, StoredFinding};

    #[test]
    fn parse_selector_type_accepts_aliases() {
        assert_eq!(
            parse_selector_type("tool_output").expect("tool_output"),
            SelectorType::ToolOutput
        );
        assert_eq!(
            parse_selector_type("tool-output").expect("tool-output"),
            SelectorType::ToolOutput
        );
        assert_eq!(
            parse_selector_type("finding").expect("finding"),
            SelectorType::Finding
        );
    }

    #[test]
    fn render_and_parse_finding_selector_roundtrip() {
        let token = render_finding_selector(
            "guardian-intelligence/apm2",
            482,
            "0123456789abcdef0123456789abcdef01234567",
            "quality",
            "qual-000042",
        );
        let parsed = parse_selector(SelectorType::Finding, &token).expect("parsed");
        match parsed {
            SelectorToken::Finding(finding) => {
                assert_eq!(finding.owner_repo, "guardian-intelligence/apm2");
                assert_eq!(finding.pr, 482);
                assert_eq!(finding.dimension, "code-quality");
                assert_eq!(finding.finding_id, "qual-000042");
            },
            SelectorToken::ToolOutput(_) => panic!("expected finding selector"),
        }
    }

    #[test]
    fn parse_finding_selector_rejects_legacy_v1_tokens() {
        let err = parse_selector(
            SelectorType::Finding,
            "finding:v1:guardian-intelligence/apm2:482:0123456789abcdef0123456789abcdef01234567:security:123:7",
        )
        .expect_err("legacy v1 selector should fail");
        assert!(err.contains("finding:v2"));
    }

    #[test]
    fn render_and_parse_tool_output_selector_roundtrip() {
        let token =
            render_tool_output_selector("0123456789abcdef0123456789abcdef01234567", "rustfmt");
        let parsed = parse_selector(SelectorType::ToolOutput, &token).expect("parsed");
        match parsed {
            SelectorToken::ToolOutput(tool) => {
                assert_eq!(tool.gate, "rustfmt");
            },
            SelectorToken::Finding(_) => panic!("expected tool output selector"),
        }
    }

    #[test]
    fn build_findings_report_is_pending_without_verdict_projection() {
        let bundle = FindingsBundle {
            schema: "apm2.fac.sha_findings.bundle.v1".to_string(),
            owner_repo: "guardian-intelligence/apm2".to_string(),
            pr_number: 482,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            source: "test".to_string(),
            updated_at: "2026-02-14T00:00:00Z".to_string(),
            integrity_hmac: None,
            dimensions: vec![
                StoredDimensionFindings {
                    dimension: SECURITY_DIMENSION.to_string(),
                    status: "PASS".to_string(),
                    verdict: Some("PASS".to_string()),
                    findings: vec![StoredFinding {
                        finding_id: "sec-000001".to_string(),
                        severity: "MAJOR".to_string(),
                        summary: "Missing auth check".to_string(),
                        details: Some("authorization guard missing on privileged path".to_string()),
                        risk: Some("auth bypass".to_string()),
                        impact: Some("privilege escalation".to_string()),
                        location: Some("src/auth.rs:44".to_string()),
                        reviewer_id: Some("fac-reviewer".to_string()),
                        model_id: None,
                        backend_id: None,
                        created_at: "2026-02-14T00:00:00Z".to_string(),
                        evidence_digest: "abc".to_string(),
                        raw_evidence_pointer: "/tmp/review.md#line-10".to_string(),
                    }],
                },
                StoredDimensionFindings {
                    dimension: CODE_QUALITY_DIMENSION.to_string(),
                    status: "PASS".to_string(),
                    verdict: Some("PASS".to_string()),
                    findings: Vec::new(),
                },
            ],
        };

        let report = build_findings_report(
            "guardian-intelligence/apm2",
            482,
            "0123456789abcdef0123456789abcdef01234567",
            Some(&bundle),
        );

        assert_eq!(report.overall_status, "PENDING");
        assert!(!report.fail_closed);
        assert_eq!(report.dimensions.len(), 2);
        assert_eq!(report.dimensions[0].status, "PENDING");
        assert_eq!(report.dimensions[1].status, "PENDING");
        assert_eq!(report.dimensions[0].verdict, "pending");
        assert_eq!(report.dimensions[1].verdict, "pending");
        assert_eq!(report.dimensions[0].findings.len(), 1);
        assert_eq!(report.dimensions[0].findings[0].finding_id, "sec-000001");
    }
}
