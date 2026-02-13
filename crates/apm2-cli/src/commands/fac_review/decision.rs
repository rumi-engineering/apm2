//! FAC-native per-dimension decision projection (`approve` / `deny`).

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use super::barrier::{ensure_gh_cli_ready, fetch_pr_head_sha, resolve_authenticated_gh_login};
use super::target::resolve_pr_target;
use super::types::{COMMENT_CONFIRM_MAX_PAGES, now_iso8601, validate_expected_head_sha};
use super::{github_projection, projection_store};
use crate::exit_codes::codes as exit_codes;

const DECISION_MARKER: &str = "apm2-review-decision:v1";
const DECISION_SCHEMA: &str = "apm2.review.decision.v1";

const SECURITY_DIMENSION: &str = "security";
const CODE_QUALITY_DIMENSION: &str = "code-quality";
const ACTIVE_DIMENSIONS: [&str; 2] = [SECURITY_DIMENSION, CODE_QUALITY_DIMENSION];

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DecisionValueArg {
    Approve,
    Deny,
}

impl DecisionValueArg {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionComment {
    schema: String,
    pr: u32,
    sha: String,
    updated_at: String,
    #[serde(default)]
    dimensions: BTreeMap<String, DecisionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionEntry {
    decision: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    set_by: String,
    #[serde(default)]
    set_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IssueComment {
    id: u64,
    body: String,
    html_url: String,
    created_at: String,
    #[serde(default)]
    user: Option<IssueUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IssueUser {
    login: String,
}

#[derive(Debug, Clone)]
struct ParsedDecisionComment {
    comment: IssueComment,
    payload: DecisionComment,
}

#[derive(Debug, Clone, Serialize)]
struct DecisionShowReport {
    schema: String,
    pr_number: u32,
    head_sha: String,
    overall_decision: String,
    fail_closed: bool,
    dimensions: Vec<DimensionDecisionView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_comment_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_comment_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DimensionDecisionView {
    dimension: String,
    decision: String,
    reason: String,
    set_by: String,
    set_at: String,
    sha: String,
}

pub fn run_decision_show(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    json_output: bool,
) -> Result<u8, String> {
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number, pr_url)?;
    let expected_author_login = resolve_expected_author_login(&owner_repo, resolved_pr)?;
    let head_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;
    let comments = fetch_issue_comments(&owner_repo, resolved_pr)?;
    let report = build_show_report(resolved_pr, &head_sha, &comments, &expected_author_login);
    emit_show_report(&report, json_output)?;
    if report.fail_closed {
        Ok(exit_codes::GENERIC_ERROR)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_decision_set(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    dimension: &str,
    decision: DecisionValueArg,
    reason: Option<&str>,
    keep_prepared_inputs: bool,
    json_output: bool,
) -> Result<u8, String> {
    ensure_gh_cli_ready()?;
    let normalized_dimension = normalize_dimension(dimension)?;
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number, pr_url)?;
    let expected_author_login = resolve_expected_author_login(&owner_repo, resolved_pr)?;
    let head_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;
    let comments = match fetch_issue_comments(&owner_repo, resolved_pr) {
        Ok(value) => value,
        Err(err)
            if err.contains("requires local projection data")
                || err.contains("GitHub read fallback is disabled") =>
        {
            Vec::new()
        },
        Err(err) => return Err(err),
    };
    let parsed = parse_decision_comments_for_author(&comments, Some(&expected_author_login));
    let latest_any = latest_decision_comment(&parsed);
    let base_for_sha = latest_for_sha(&parsed, &head_sha);

    let mut payload = base_for_sha.map_or_else(
        || DecisionComment {
            schema: DECISION_SCHEMA.to_string(),
            pr: resolved_pr,
            sha: head_sha.clone(),
            updated_at: now_iso8601(),
            dimensions: BTreeMap::new(),
        },
        |existing| existing.payload.clone(),
    );

    payload.schema = DECISION_SCHEMA.to_string();
    payload.pr = resolved_pr;
    payload.sha.clone_from(&head_sha);
    payload.updated_at = now_iso8601();

    let actor = expected_author_login.clone();
    payload.dimensions.insert(
        normalized_dimension.to_string(),
        DecisionEntry {
            decision: decision.as_str().to_string(),
            reason: reason.unwrap_or_default().trim().to_string(),
            set_by: actor,
            set_at: now_iso8601(),
        },
    );

    let active_comment_id = if let Some(existing) = latest_any {
        update_decision_comment(&owner_repo, existing.comment.id, &payload)?;
        existing.comment.id
    } else {
        create_decision_comment(&owner_repo, resolved_pr, &payload)?
    };

    let report = build_report_from_payload(
        resolved_pr,
        &head_sha,
        &payload,
        Some(active_comment_id),
        Some(format!(
            "https://github.com/{owner_repo}/pull/{resolved_pr}#issuecomment-{active_comment_id}"
        )),
        false,
        Vec::new(),
    );
    let _ = cache_written_decision_comment(
        &owner_repo,
        resolved_pr,
        active_comment_id,
        &payload,
        &expected_author_login,
    );
    let _ = projection_store::save_identity_with_context(
        &owner_repo,
        resolved_pr,
        &head_sha,
        "decision.set",
    );
    let _ = projection_store::save_trusted_reviewer_id(
        &owner_repo,
        resolved_pr,
        &expected_author_login,
    );
    emit_show_report(&report, json_output)?;
    if !keep_prepared_inputs {
        if let Err(err) =
            super::prepare::cleanup_prepared_review_inputs(&owner_repo, resolved_pr, &head_sha)
        {
            eprintln!("WARNING: failed to clean prepared review inputs: {err}");
        }
    }
    terminate_review_agent(resolved_pr, normalized_dimension);
    Ok(exit_codes::SUCCESS)
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

    if !projection_store::gh_read_fallback_enabled() {
        return Err(projection_store::gh_read_fallback_disabled_error(
            "decision.resolve_head_sha",
        ));
    }

    ensure_gh_cli_ready()?;
    let value = fetch_pr_head_sha(owner_repo, pr_number)?;
    validate_expected_head_sha(&value)?;
    let value = value.to_ascii_lowercase();
    let _ =
        projection_store::record_fallback_read(owner_repo, pr_number, "decision.resolve_head_sha");
    let _ = projection_store::save_identity_with_context(
        owner_repo,
        pr_number,
        &value,
        "gh-fallback:decision.resolve_head_sha",
    );
    Ok(value)
}

fn normalize_dimension(input: &str) -> Result<&'static str, String> {
    let normalized = input.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "security" => Ok(SECURITY_DIMENSION),
        "quality" | "code-quality" => Ok(CODE_QUALITY_DIMENSION),
        other => Err(format!(
            "unsupported dimension `{other}` (expected security|code-quality)"
        )),
    }
}

fn fetch_issue_comments(owner_repo: &str, pr_number: u32) -> Result<Vec<IssueComment>, String> {
    if let Some(cached) =
        projection_store::load_issue_comments_cache::<IssueComment>(owner_repo, pr_number)?
    {
        return Ok(cached);
    }

    if !projection_store::gh_read_fallback_enabled() {
        return Err(projection_store::gh_read_fallback_disabled_error(
            "decision.fetch_issue_comments",
        ));
    }

    ensure_gh_cli_ready()?;
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
    let _ = projection_store::record_fallback_read(
        owner_repo,
        pr_number,
        "decision.fetch_issue_comments",
    );
    let _ = projection_store::save_issue_comments_cache(owner_repo, pr_number, &collected);
    Ok(collected)
}

fn resolve_expected_author_login(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    if let Some(cached) = projection_store::load_trusted_reviewer_id(owner_repo, pr_number)? {
        return Ok(cached);
    }

    if !projection_store::gh_read_fallback_enabled() {
        return Err(projection_store::gh_read_fallback_disabled_error(
            "decision.resolve_expected_author_login",
        ));
    }

    ensure_gh_cli_ready()?;
    let login = resolve_authenticated_gh_login().ok_or_else(|| {
        "failed to resolve authenticated GitHub login for trusted projection comment filtering"
            .to_string()
    })?;
    let _ = projection_store::record_fallback_read(
        owner_repo,
        pr_number,
        "decision.resolve_expected_author_login",
    );
    let _ = projection_store::save_trusted_reviewer_id(owner_repo, pr_number, &login);
    Ok(login)
}

fn parse_decision_comments_for_author(
    comments: &[IssueComment],
    expected_author_login: Option<&str>,
) -> Vec<ParsedDecisionComment> {
    let expected_author_lower = expected_author_login.map(str::to_ascii_lowercase);
    comments
        .iter()
        .filter(|comment| {
            expected_author_lower
                .as_deref()
                .is_none_or(|expected_author| {
                    comment
                        .user
                        .as_ref()
                        .is_some_and(|author| author.login.eq_ignore_ascii_case(expected_author))
                })
        })
        .filter(|comment| {
            comment
                .body
                .contains(&format!("<!-- {DECISION_MARKER} -->"))
        })
        .filter_map(|comment| parse_decision_comment(comment).ok())
        .collect()
}

fn parse_decision_comment(comment: &IssueComment) -> Result<ParsedDecisionComment, String> {
    let yaml_block = extract_fenced_yaml(&comment.body)
        .ok_or_else(|| "missing fenced yaml block in decision comment".to_string())?;
    let payload: DecisionComment = serde_yaml::from_str(yaml_block)
        .map_err(|err| format!("failed to parse decision yaml: {err}"))?;
    if payload.schema != DECISION_SCHEMA {
        return Err(format!("invalid decision schema `{}`", payload.schema));
    }
    validate_expected_head_sha(&payload.sha)?;
    Ok(ParsedDecisionComment {
        comment: comment.clone(),
        payload,
    })
}

fn extract_fenced_yaml(body: &str) -> Option<&str> {
    let start_marker = "```yaml\n";
    let start = body.find(start_marker)?;
    let yaml_start = start + start_marker.len();
    let end = body[yaml_start..].find("\n```")?;
    Some(body[yaml_start..yaml_start + end].trim())
}

fn latest_decision_comment(entries: &[ParsedDecisionComment]) -> Option<&ParsedDecisionComment> {
    entries.iter().max_by(|a, b| {
        (&a.comment.created_at, a.comment.id).cmp(&(&b.comment.created_at, b.comment.id))
    })
}

fn latest_for_sha<'a>(
    entries: &'a [ParsedDecisionComment],
    sha: &str,
) -> Option<&'a ParsedDecisionComment> {
    entries
        .iter()
        .filter(|entry| entry.payload.sha.eq_ignore_ascii_case(sha))
        .max_by(|a, b| {
            (&a.comment.created_at, a.comment.id).cmp(&(&b.comment.created_at, b.comment.id))
        })
}

fn build_show_report(
    pr_number: u32,
    head_sha: &str,
    comments: &[IssueComment],
    expected_author_login: &str,
) -> DecisionShowReport {
    let parsed = parse_decision_comments_for_author(comments, Some(expected_author_login));
    if parsed.is_empty() {
        return DecisionShowReport {
            schema: "apm2.fac.review.decision.show.v1".to_string(),
            pr_number,
            head_sha: head_sha.to_string(),
            overall_decision: "unknown".to_string(),
            fail_closed: true,
            dimensions: build_unknown_dimension_views(head_sha),
            source_comment_id: None,
            source_comment_url: None,
            errors: vec![format!(
                "decision marker comment not found for trusted login `{expected_author_login}`"
            )],
        };
    }

    let matching = parsed
        .iter()
        .filter(|entry| entry.payload.sha.eq_ignore_ascii_case(head_sha))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return DecisionShowReport {
            schema: "apm2.fac.review.decision.show.v1".to_string(),
            pr_number,
            head_sha: head_sha.to_string(),
            overall_decision: "unknown".to_string(),
            fail_closed: true,
            dimensions: build_unknown_dimension_views(head_sha),
            source_comment_id: None,
            source_comment_url: None,
            errors: vec![format!(
                "no decision projection bound to head sha {head_sha}"
            )],
        };
    }

    let mut signatures = BTreeSet::new();
    for entry in &matching {
        signatures.insert(signature_for_payload(&entry.payload));
    }
    if signatures.len() > 1 {
        return DecisionShowReport {
            schema: "apm2.fac.review.decision.show.v1".to_string(),
            pr_number,
            head_sha: head_sha.to_string(),
            overall_decision: "unknown".to_string(),
            fail_closed: true,
            dimensions: build_unknown_dimension_views(head_sha),
            source_comment_id: None,
            source_comment_url: None,
            errors: vec![
                "multiple decision comments for the same sha disagree on effective state"
                    .to_string(),
            ],
        };
    }

    let selected = matching.into_iter().max_by(|a, b| {
        (&a.comment.created_at, a.comment.id).cmp(&(&b.comment.created_at, b.comment.id))
    });
    selected.map_or_else(
        || DecisionShowReport {
            schema: "apm2.fac.review.decision.show.v1".to_string(),
            pr_number,
            head_sha: head_sha.to_string(),
            overall_decision: "unknown".to_string(),
            fail_closed: true,
            dimensions: build_unknown_dimension_views(head_sha),
            source_comment_id: None,
            source_comment_url: None,
            errors: vec!["internal selection error".to_string()],
        },
        |value| {
            build_report_from_payload(
                pr_number,
                head_sha,
                &value.payload,
                Some(value.comment.id),
                Some(value.comment.html_url.clone()),
                true,
                Vec::new(),
            )
        },
    )
}

fn build_report_from_payload(
    pr_number: u32,
    head_sha: &str,
    payload: &DecisionComment,
    source_comment_id: Option<u64>,
    source_comment_url: Option<String>,
    fail_closed_on_unknown: bool,
    mut errors: Vec<String>,
) -> DecisionShowReport {
    let mut dimensions = Vec::new();
    let mut fail_closed = false;
    for dimension in ACTIVE_DIMENSIONS {
        let view = if let Some(entry) = payload.dimensions.get(dimension) {
            let decision = normalize_decision_value(&entry.decision).unwrap_or("unknown");
            if decision == "unknown" {
                fail_closed = true;
                errors.push(format!(
                    "dimension `{dimension}` has invalid decision `{}`",
                    entry.decision
                ));
            }
            DimensionDecisionView {
                dimension: dimension.to_string(),
                decision: decision.to_string(),
                reason: entry.reason.clone(),
                set_by: entry.set_by.clone(),
                set_at: entry.set_at.clone(),
                sha: payload.sha.clone(),
            }
        } else {
            fail_closed = true;
            errors.push(format!("dimension `{dimension}` decision is missing"));
            DimensionDecisionView {
                dimension: dimension.to_string(),
                decision: "unknown".to_string(),
                reason: String::new(),
                set_by: String::new(),
                set_at: String::new(),
                sha: payload.sha.clone(),
            }
        };
        dimensions.push(view);
    }

    let overall_decision = aggregate_overall_decision(&dimensions);
    if fail_closed_on_unknown && overall_decision == "unknown" {
        fail_closed = true;
    }
    DecisionShowReport {
        schema: "apm2.fac.review.decision.show.v1".to_string(),
        pr_number,
        head_sha: head_sha.to_string(),
        overall_decision: overall_decision.to_string(),
        fail_closed,
        dimensions,
        source_comment_id,
        source_comment_url,
        errors,
    }
}

fn build_unknown_dimension_views(head_sha: &str) -> Vec<DimensionDecisionView> {
    ACTIVE_DIMENSIONS
        .iter()
        .map(|dimension| DimensionDecisionView {
            dimension: (*dimension).to_string(),
            decision: "unknown".to_string(),
            reason: String::new(),
            set_by: String::new(),
            set_at: String::new(),
            sha: head_sha.to_string(),
        })
        .collect()
}

fn normalize_decision_value(input: &str) -> Option<&'static str> {
    match input.trim().to_ascii_lowercase().as_str() {
        "approve" => Some("approve"),
        "deny" => Some("deny"),
        _ => None,
    }
}

fn aggregate_overall_decision(dimensions: &[DimensionDecisionView]) -> &'static str {
    if dimensions
        .iter()
        .any(|dimension| dimension.decision == "deny")
    {
        return "deny";
    }
    if dimensions
        .iter()
        .all(|dimension| dimension.decision == "approve")
    {
        return "approve";
    }
    "unknown"
}

fn signature_for_payload(payload: &DecisionComment) -> String {
    ACTIVE_DIMENSIONS
        .iter()
        .map(|dimension| {
            let value = payload
                .dimensions
                .get(*dimension)
                .map_or("missing", |entry| {
                    normalize_decision_value(&entry.decision).unwrap_or("unknown")
                });
            format!("{dimension}:{value}")
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn render_decision_comment_body(payload: &DecisionComment) -> Result<String, String> {
    let yaml = serde_yaml::to_string(payload)
        .map_err(|err| format!("failed to serialize decision payload: {err}"))?;
    Ok(format!(
        "<!-- {DECISION_MARKER} -->\n```yaml\n# {DECISION_MARKER}\n{yaml}```\n"
    ))
}

fn create_decision_comment(
    owner_repo: &str,
    pr_number: u32,
    payload: &DecisionComment,
) -> Result<u64, String> {
    let body = render_decision_comment_body(payload)?;
    github_projection::create_issue_comment(owner_repo, pr_number, &body).map(|value| value.id)
}

fn update_decision_comment(
    owner_repo: &str,
    comment_id: u64,
    payload: &DecisionComment,
) -> Result<(), String> {
    let body = render_decision_comment_body(payload)?;
    github_projection::update_issue_comment(owner_repo, comment_id, &body)
}

fn cache_written_decision_comment(
    owner_repo: &str,
    pr_number: u32,
    comment_id: u64,
    payload: &DecisionComment,
    trusted_login: &str,
) -> Result<(), String> {
    let body = render_decision_comment_body(payload)?;
    let mut comments =
        projection_store::load_issue_comments_cache::<IssueComment>(owner_repo, pr_number)?
            .unwrap_or_default();

    if let Some(existing) = comments.iter_mut().find(|comment| comment.id == comment_id) {
        existing.body = body;
        existing.user = Some(IssueUser {
            login: trusted_login.to_string(),
        });
    } else {
        comments.push(IssueComment {
            id: comment_id,
            body,
            html_url: format!(
                "https://github.com/{owner_repo}/pull/{pr_number}#issuecomment-{comment_id}"
            ),
            created_at: now_iso8601(),
            user: Some(IssueUser {
                login: trusted_login.to_string(),
            }),
        });
    }

    projection_store::save_issue_comments_cache(owner_repo, pr_number, &comments)
}

fn emit_show_report(report: &DecisionShowReport, json_output: bool) -> Result<(), String> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(report)
                .map_err(|err| format!("failed to serialize decision report: {err}"))?
        );
        return Ok(());
    }

    println!("FAC Review Decision");
    println!("  PR:            #{}", report.pr_number);
    println!("  Head SHA:      {}", report.head_sha);
    println!("  Overall:       {}", report.overall_decision);
    if let Some(url) = &report.source_comment_url {
        println!("  Source:        {url}");
    }
    for dimension in &report.dimensions {
        println!("  - {}: {}", dimension.dimension, dimension.decision);
        if !dimension.reason.is_empty() {
            println!("      reason: {}", dimension.reason);
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

fn dimension_to_state_review_type(dimension: &str) -> &str {
    match dimension {
        "code-quality" => "quality",
        other => other,
    }
}

fn terminate_review_agent(pr_number: u32, dimension: &str) {
    let review_type = dimension_to_state_review_type(dimension);
    let Ok(Some(state)) = super::state::load_review_run_state_strict(pr_number, review_type) else {
        return;
    };
    let Some(pid) = state.pid else { return };
    if !super::state::is_process_alive(pid) {
        return;
    }
    // Verify process identity to avoid killing a reused PID.
    if let Some(recorded) = state.proc_start_time {
        let observed = super::state::get_process_start_time(pid);
        if observed != Some(recorded) {
            eprintln!("WARNING: skipping agent termination: pid {pid} identity mismatch");
            return;
        }
    }
    // SIGTERM → wait → SIGKILL
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let deadline = std::time::Instant::now() + super::types::TERMINATE_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if !super::state::is_process_alive(pid) {
            eprintln!("INFO: terminated review agent pid={pid} after decision set");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = std::process::Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
    eprintln!("WARNING: sent SIGKILL to review agent pid={pid}");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        CODE_QUALITY_DIMENSION, DECISION_SCHEMA, DecisionComment, DecisionEntry,
        DimensionDecisionView, IssueComment, IssueUser, aggregate_overall_decision,
        normalize_decision_value, normalize_dimension, parse_decision_comments_for_author,
        render_decision_comment_body, signature_for_payload,
    };

    #[test]
    fn test_normalize_dimension_aliases() {
        assert_eq!(
            normalize_dimension("security").expect("security"),
            "security"
        );
        assert_eq!(
            normalize_dimension("quality").expect("quality"),
            CODE_QUALITY_DIMENSION
        );
        assert_eq!(
            normalize_dimension("code_quality").expect("code_quality"),
            CODE_QUALITY_DIMENSION
        );
    }

    #[test]
    fn test_normalize_decision_value() {
        assert_eq!(normalize_decision_value("approve"), Some("approve"));
        assert_eq!(normalize_decision_value("DENY"), Some("deny"));
        assert_eq!(normalize_decision_value("noop"), None);
    }

    #[test]
    fn test_aggregate_overall_decision_deny_wins() {
        let dimensions = vec![
            DimensionDecisionView {
                dimension: "security".to_string(),
                decision: "approve".to_string(),
                reason: String::new(),
                set_by: String::new(),
                set_at: String::new(),
                sha: "abc".to_string(),
            },
            DimensionDecisionView {
                dimension: CODE_QUALITY_DIMENSION.to_string(),
                decision: "deny".to_string(),
                reason: String::new(),
                set_by: String::new(),
                set_at: String::new(),
                sha: "abc".to_string(),
            },
        ];
        assert_eq!(aggregate_overall_decision(&dimensions), "deny");
    }

    #[test]
    fn test_signature_for_payload_is_stable() {
        let mut dimensions = BTreeMap::new();
        dimensions.insert(
            "security".to_string(),
            DecisionEntry {
                decision: "approve".to_string(),
                reason: String::new(),
                set_by: String::new(),
                set_at: String::new(),
            },
        );
        dimensions.insert(
            CODE_QUALITY_DIMENSION.to_string(),
            DecisionEntry {
                decision: "deny".to_string(),
                reason: String::new(),
                set_by: String::new(),
                set_at: String::new(),
            },
        );
        let payload = DecisionComment {
            schema: DECISION_SCHEMA.to_string(),
            pr: 441,
            sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            updated_at: "2026-02-11T00:00:00Z".to_string(),
            dimensions,
        };
        assert_eq!(
            signature_for_payload(&payload),
            "security:approve|code-quality:deny"
        );
    }

    #[test]
    fn test_render_decision_comment_body_contains_marker() {
        let payload = DecisionComment {
            schema: DECISION_SCHEMA.to_string(),
            pr: 441,
            sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            updated_at: "2026-02-11T00:00:00Z".to_string(),
            dimensions: BTreeMap::new(),
        };
        let body = render_decision_comment_body(&payload).expect("body");
        assert!(body.contains("apm2-review-decision:v1"));
        assert!(body.contains("```yaml"));
    }

    #[test]
    fn test_parse_decision_comments_filters_untrusted_authors() {
        let body = r#"<!-- apm2-review-decision:v1 -->
```yaml
schema: apm2.review.decision.v1
pr: 441
sha: 0123456789abcdef0123456789abcdef01234567
updated_at: 2026-02-11T00:00:00Z
dimensions:
  security:
    decision: approve
    reason: ""
    set_by: fac-bot
    set_at: 2026-02-11T00:00:00Z
```
"#;
        let trusted = IssueComment {
            id: 1,
            body: body.to_string(),
            html_url: "https://example.invalid/comment/1".to_string(),
            created_at: "2026-02-11T00:00:00Z".to_string(),
            user: Some(IssueUser {
                login: "fac-bot".to_string(),
            }),
        };
        let spoofed = IssueComment {
            id: 2,
            body: body.to_string(),
            html_url: "https://example.invalid/comment/2".to_string(),
            created_at: "2026-02-11T00:01:00Z".to_string(),
            user: Some(IssueUser {
                login: "spoofed-user".to_string(),
            }),
        };

        let parsed = parse_decision_comments_for_author(&[trusted, spoofed], Some("fac-bot"));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].comment.id, 1);
    }
}
