//! Admission control: event context resolution and trust-boundary enforcement.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::events::emit_review_event;
use super::types::{
    FacEventContext, MAX_EVENT_PAYLOAD_BYTES, now_iso8601_millis, split_owner_repo,
    validate_expected_head_sha,
};
use crate::commands::fac_pr::GitHubPrClient;

// ── Event context resolution ────────────────────────────────────────────────

pub fn resolve_fac_event_context(
    repo: &str,
    event_path: &Path,
    event_name: &str,
) -> Result<FacEventContext, String> {
    let _ = split_owner_repo(repo)?;
    let payload_text = read_event_payload_bounded(event_path, MAX_EVENT_PAYLOAD_BYTES)?;
    let payload: serde_json::Value =
        serde_json::from_str(&payload_text).map_err(|err| format!("invalid event JSON: {err}"))?;

    match event_name {
        "pull_request" | "pull_request_target" => {
            resolve_pull_request_context(repo, event_name, &payload)
        },
        "workflow_dispatch" => resolve_workflow_dispatch_context(repo, &payload),
        other => Err(format!(
            "unsupported event_name `{other}`; expected pull_request, pull_request_target, or workflow_dispatch"
        )),
    }
}

pub fn read_event_payload_bounded(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|err| format!("failed to open event payload {}: {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to stat event payload {}: {err}", path.display()))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "event payload {} is too large ({} bytes > {} byte limit)",
            path.display(),
            metadata.len(),
            max_bytes
        ));
    }

    let mut reader = (&mut file).take(max_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|err| format!("failed to read event payload {}: {err}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(format!(
            "event payload {} exceeds {} byte limit",
            path.display(),
            max_bytes
        ));
    }

    String::from_utf8(bytes)
        .map_err(|err| format!("event payload {} is not valid UTF-8: {err}", path.display()))
}

// ── Barrier enforcement ─────────────────────────────────────────────────────

pub fn enforce_barrier(ctx: &FacEventContext) -> Result<(), String> {
    validate_expected_head_sha(&ctx.head_sha)?;
    if !is_allowed_author_association(&ctx.author_association) {
        return Err(format!(
            "unauthorized PR author identity: {} ({})",
            ctx.author_login, ctx.author_association
        ));
    }

    if ctx.event_name == "workflow_dispatch" {
        let permission = ctx.actor_permission.as_deref().unwrap_or("none");
        if !matches!(permission, "admin" | "maintain" | "write") {
            return Err(format!(
                "workflow_dispatch actor `{}` lacks repository permission (need write|maintain|admin, got `{permission}`)",
                ctx.actor_login
            ));
        }

        let dispatch_ref = resolve_dispatch_ref_name();
        if dispatch_ref.is_empty() {
            return Err(
                "workflow_dispatch trusted-ref check failed: missing GITHUB_REF_NAME".to_string(),
            );
        }
        if dispatch_ref != ctx.base_ref && dispatch_ref != ctx.default_branch {
            return Err(format!(
                "workflow_dispatch ref `{dispatch_ref}` is not trusted for PR base `{}` (default `{}`)",
                ctx.base_ref, ctx.default_branch
            ));
        }
    }

    Ok(())
}

pub fn is_allowed_author_association(value: &str) -> bool {
    matches!(value, "OWNER" | "MEMBER" | "COLLABORATOR")
}

fn resolve_dispatch_ref_name() -> String {
    if let Ok(ref_name) = std::env::var("GITHUB_REF_NAME") {
        if !ref_name.is_empty() {
            return ref_name;
        }
    }
    if let Ok(full_ref) = std::env::var("GITHUB_REF") {
        if let Some(stripped) = full_ref.strip_prefix("refs/heads/") {
            return stripped.to_string();
        }
    }
    String::new()
}

// ── Barrier decision events ─────────────────────────────────────────────────

pub fn emit_barrier_decision_event(
    source: &str,
    repo: &str,
    event_name: &str,
    ctx: Option<&FacEventContext>,
    passed: bool,
    reason: Option<&str>,
) -> Result<(), String> {
    let event = build_barrier_decision_event(source, repo, event_name, ctx, passed, reason);
    emit_review_event(&event)
}

pub fn build_barrier_decision_event(
    source: &str,
    repo: &str,
    event_name: &str,
    ctx: Option<&FacEventContext>,
    passed: bool,
    reason: Option<&str>,
) -> serde_json::Value {
    let mut envelope = serde_json::Map::new();
    envelope.insert("ts".to_string(), serde_json::json!(now_iso8601_millis()));
    envelope.insert("event".to_string(), serde_json::json!("barrier_decision"));
    envelope.insert("phase".to_string(), serde_json::json!(source));
    envelope.insert(
        "result".to_string(),
        serde_json::json!(if passed { "pass" } else { "fail" }),
    );
    envelope.insert("repo".to_string(), serde_json::json!(repo));
    envelope.insert("event_name".to_string(), serde_json::json!(event_name));
    envelope.insert(
        "pr_number".to_string(),
        serde_json::json!(ctx.map_or(0, |value| value.pr_number)),
    );
    envelope.insert(
        "head_sha".to_string(),
        serde_json::json!(ctx.map_or("-", |value| value.head_sha.as_str())),
    );
    envelope.insert(
        "author_association".to_string(),
        serde_json::json!(ctx.map_or("-", |value| value.author_association.as_str())),
    );
    envelope.insert(
        "actor_login".to_string(),
        serde_json::json!(ctx.map_or("-", |value| value.actor_login.as_str())),
    );
    if let Some(value) = ctx.and_then(|value| value.actor_permission.as_deref()) {
        envelope.insert("actor_permission".to_string(), serde_json::json!(value));
    }
    if let Some(value) = reason {
        envelope.insert("reason".to_string(), serde_json::json!(value));
    }
    serde_json::Value::Object(envelope)
}

// ── GitHub context resolvers ────────────────────────────────────────────────

fn resolve_pull_request_context(
    repo: &str,
    event_name: &str,
    payload: &serde_json::Value,
) -> Result<FacEventContext, String> {
    let event_repo = payload
        .pointer("/repository/full_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing repository.full_name in event payload".to_string())?;
    if event_repo != repo {
        return Err(format!(
            "event repository mismatch: expected `{repo}`, got `{event_repo}`"
        ));
    }

    let pr_number = payload
        .pointer("/pull_request/number")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "missing pull_request.number in event payload".to_string())
        .and_then(|value| {
            u32::try_from(value).map_err(|_| format!("invalid pull_request.number: {value}"))
        })?;
    let pr_url = payload
        .pointer("/pull_request/html_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.html_url in event payload".to_string())?
        .to_string();
    let head_sha = payload
        .pointer("/pull_request/head/sha")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.head.sha in event payload".to_string())?
        .to_string();
    let base_ref = payload
        .pointer("/pull_request/base/ref")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.base.ref in event payload".to_string())?
        .to_string();
    let default_branch = payload
        .pointer("/repository/default_branch")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing repository.default_branch in event payload".to_string())?
        .to_string();
    let author_login = payload
        .pointer("/pull_request/user/login")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.user.login in event payload".to_string())?
        .to_string();
    let author_association = payload
        .pointer("/pull_request/author_association")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.author_association in event payload".to_string())?
        .to_string();
    let actor_login = resolve_actor_login(payload);

    Ok(FacEventContext {
        repo: repo.to_string(),
        event_name: event_name.to_string(),
        pr_number,
        pr_url,
        head_sha,
        base_ref,
        default_branch,
        author_login,
        author_association,
        actor_login,
        actor_permission: None,
    })
}

fn resolve_workflow_dispatch_context(
    repo: &str,
    payload: &serde_json::Value,
) -> Result<FacEventContext, String> {
    let event_repo = payload
        .pointer("/repository/full_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing repository.full_name in event payload".to_string())?;
    if event_repo != repo {
        return Err(format!(
            "event repository mismatch: expected `{repo}`, got `{event_repo}`"
        ));
    }

    let pr_number_raw = payload
        .pointer("/inputs/pr_number")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "workflow_dispatch requires inputs.pr_number".to_string())?;
    let pr_number = pr_number_raw
        .parse::<u32>()
        .map_err(|err| format!("invalid inputs.pr_number `{pr_number_raw}`: {err}"))?;
    if pr_number == 0 {
        return Err("inputs.pr_number must be greater than zero".to_string());
    }

    let pr_data = fetch_pr_data(repo, pr_number)?;
    let pr_url = pr_data
        .pointer("/html_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing html_url from PR API response".to_string())?
        .to_string();
    let head_sha = pr_data
        .pointer("/head/sha")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing head.sha from PR API response".to_string())?
        .to_string();
    let base_ref = pr_data
        .pointer("/base/ref")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing base.ref from PR API response".to_string())?
        .to_string();
    let author_login = pr_data
        .pointer("/user/login")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing user.login from PR API response".to_string())?
        .to_string();
    let author_association = pr_data
        .pointer("/author_association")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing author_association from PR API response".to_string())?
        .to_string();

    let default_branch = payload
        .pointer("/repository/default_branch")
        .and_then(serde_json::Value::as_str)
        .map_or_else(
            || fetch_default_branch(repo).unwrap_or_else(|_| "main".to_string()),
            ToString::to_string,
        );
    let actor_login = resolve_actor_login(payload);
    let actor_permission = resolve_actor_permission(repo, &actor_login)?;

    Ok(FacEventContext {
        repo: repo.to_string(),
        event_name: "workflow_dispatch".to_string(),
        pr_number,
        pr_url,
        head_sha,
        base_ref,
        default_branch,
        author_login,
        author_association,
        actor_login,
        actor_permission: Some(actor_permission),
    })
}

fn resolve_actor_login(payload: &serde_json::Value) -> String {
    std::env::var("GITHUB_ACTOR")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            payload
                .pointer("/sender/login")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

// ── GitHub API helpers ──────────────────────────────────────────────────────

pub fn fetch_default_branch(repo: &str) -> Result<String, String> {
    let client = GitHubPrClient::new(repo)?;
    client.fetch_default_branch()
}

pub fn fetch_pr_data(repo: &str, pr_number: u32) -> Result<serde_json::Value, String> {
    let client = GitHubPrClient::new(repo)?;
    client.fetch_pr_data(pr_number)
}

pub fn resolve_actor_permission(repo: &str, actor: &str) -> Result<String, String> {
    let client = GitHubPrClient::new(repo)?;
    client.resolve_actor_permission(actor)
}

pub fn fetch_pr_head_sha(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    let client = GitHubPrClient::new(owner_repo)?;
    client.head_sha(pr_number)
}

pub fn ensure_gh_cli_ready(repo: &str) -> Result<(), String> {
    GitHubPrClient::new(repo)?.auth_check().map(|_| ())
}

pub fn resolve_authenticated_gh_login(repo: &str) -> Option<String> {
    let info = GitHubPrClient::new(repo).ok()?.auth_check().ok()?;
    let login = info.login;
    if login.is_empty() { None } else { Some(login) }
}

pub fn confirm_review_posted(
    owner_repo: &str,
    pr_number: u32,
    marker: &str,
    head_sha: &str,
    expected_author_login: Option<&str>,
) -> Result<Option<super::types::PostedReview>, String> {
    let client = GitHubPrClient::new(owner_repo)?;
    let max_pages = u32::try_from(super::types::COMMENT_CONFIRM_MAX_PAGES).unwrap_or(20);
    let comments = client.read_comments(pr_number, max_pages)?;

    let marker_lower = marker.to_ascii_lowercase();
    let head_sha_lower = head_sha.to_ascii_lowercase();
    let expected_author_lower = expected_author_login.map(str::to_ascii_lowercase);

    for comment in comments.iter().rev() {
        let body_lower = comment.body.to_ascii_lowercase();
        if !(body_lower.contains(&marker_lower) && body_lower.contains(&head_sha_lower)) {
            continue;
        }

        if let Some(expected_author) = expected_author_lower.as_deref() {
            if comment.author.login.to_ascii_lowercase() != expected_author {
                continue;
            }
        }

        if comment.id != 0 {
            return Ok(Some(super::types::PostedReview {
                id: comment.id,
                verdict: super::detection::extract_verdict_from_comment_body(&comment.body),
            }));
        }
    }
    Ok(None)
}

pub fn confirm_review_posted_with_retry(
    owner_repo: &str,
    pr_number: u32,
    marker: &str,
    head_sha: &str,
    expected_author_login: Option<&str>,
) -> Result<Option<super::types::PostedReview>, String> {
    for attempt in 0..super::types::COMMENT_CONFIRM_MAX_ATTEMPTS {
        let maybe_review = confirm_review_posted(
            owner_repo,
            pr_number,
            marker,
            head_sha,
            expected_author_login,
        )?;
        if maybe_review.is_some() {
            return Ok(maybe_review);
        }
        if attempt + 1 < super::types::COMMENT_CONFIRM_MAX_ATTEMPTS {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    Ok(None)
}
