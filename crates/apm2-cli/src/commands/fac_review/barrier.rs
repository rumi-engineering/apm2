//! Admission control: event context resolution and trust-boundary enforcement.
#![allow(dead_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

use super::events::emit_review_event;
use super::types::{
    FacEventContext, MAX_EVENT_PAYLOAD_BYTES, QUALITY_MARKER, SECURITY_MARKER, now_iso8601_millis,
    split_owner_repo, validate_expected_head_sha,
};

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
    let output = Command::new("gh")
        .args(["api", &format!("/repos/{repo}")])
        .output()
        .map_err(|err| format!("failed to execute gh api for default branch: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving default branch: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid JSON from default branch API response: {err}"))?;
    value
        .get("default_branch")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "default_branch missing from repository API response".to_string())
}

pub fn fetch_pr_data(repo: &str, pr_number: u32) -> Result<serde_json::Value, String> {
    let output = Command::new("gh")
        .args(["api", &format!("/repos/{repo}/pulls/{pr_number}")])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR metadata: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving PR #{pr_number}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid JSON from PR metadata API response: {err}"))
}

pub fn resolve_actor_permission(repo: &str, actor: &str) -> Result<String, String> {
    if actor.is_empty() || actor == "unknown" {
        return Ok("none".to_string());
    }
    let output = Command::new("gh")
        .args([
            "api",
            &format!("/repos/{repo}/collaborators/{actor}/permission"),
        ])
        .output()
        .map_err(|err| format!("failed to execute gh api for actor permission: {err}"))?;
    if !output.status.success() {
        return Ok("none".to_string());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid JSON from actor permission API response: {err}"))?;
    Ok(value
        .get("permission")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("none")
        .to_string())
}

pub fn fetch_pr_head_sha(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    let output = Command::new("gh")
        .args(["api", &endpoint, "--jq", ".head.sha"])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR head SHA: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving PR head SHA: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sha.is_empty() {
        return Err("gh api returned empty head sha".to_string());
    }
    Ok(sha)
}

pub fn fetch_pr_head_sha_local(pr_number: u32) -> Result<String, String> {
    let owner_repo = super::target::derive_repo_from_origin()?;

    if let Some(identity) = super::projection_store::load_pr_identity(&owner_repo, pr_number)? {
        validate_expected_head_sha(&identity.head_sha)?;
        return Ok(identity.head_sha.to_ascii_lowercase());
    }

    if let Ok(branch) = super::target::current_branch() {
        if let Some(identity) = super::projection_store::load_branch_identity(&owner_repo, &branch)?
        {
            if identity.pr_number == pr_number {
                validate_expected_head_sha(&identity.head_sha)?;
                return Ok(identity.head_sha.to_ascii_lowercase());
            }
        }
    }

    if let Some(value) = super::state::resolve_local_review_head_sha(pr_number) {
        return Ok(value);
    }

    Err(format!(
        "missing local head SHA for PR #{pr_number}; run local FAC push/dispatch first or pass --sha explicitly"
    ))
}

pub fn ensure_gh_cli_ready() -> Result<(), String> {
    let output = Command::new("gh")
        .args(["auth", "status"])
        .output()
        .map_err(|err| format!("failed to execute `gh auth status`: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if detail.is_empty() {
            Err("`gh auth status` failed; authenticate the VPS runner with GitHub CLI".to_string())
        } else {
            Err(format!(
                "`gh auth status` failed; authenticate the VPS runner with GitHub CLI ({detail})"
            ))
        }
    }
}

pub fn resolve_local_reviewer_identity() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown_local_user".to_string())
}

pub fn resolve_authenticated_gh_login() -> Option<String> {
    let output = Command::new("gh")
        .args(["api", "user", "--jq", ".login"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let login = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if login.is_empty() { None } else { Some(login) }
}

fn review_type_for_marker(marker: &str) -> Option<&'static str> {
    if marker == SECURITY_MARKER {
        Some("security")
    } else if marker == QUALITY_MARKER {
        Some("code-quality")
    } else {
        None
    }
}

fn comment_matches_review_dimension(body_lower: &str, review_type: &str) -> bool {
    match review_type {
        "security" => body_lower.contains("## security review:"),
        "code-quality" => {
            body_lower.contains("## code quality review:")
                || body_lower.contains("## quality review:")
        },
        _ => false,
    }
}

fn strip_existing_metadata_block(body: &str, marker: &str) -> String {
    let pattern = format!(r"(?s){}\s*```json.*?```", regex::escape(marker));
    let Ok(re) = regex::Regex::new(&pattern) else {
        return body.to_string();
    };
    re.replacen(body, 1, "").to_string()
}

fn build_generated_metadata_block(
    marker: &str,
    review_type: &str,
    pr_number: u32,
    head_sha: &str,
    reviewer_id: &str,
    verdict: &str,
) -> Result<String, String> {
    let payload = serde_json::json!({
        "schema": "apm2.review.metadata.v1",
        "review_type": review_type,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "verdict": verdict,
        "reviewer_id": reviewer_id,
    });
    let json = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("failed to serialize generated review metadata: {err}"))?;
    Ok(format!("{marker}\n```json\n{json}\n```"))
}

pub(super) fn render_comment_with_generated_metadata(
    body: &str,
    marker: &str,
    review_type: &str,
    pr_number: u32,
    head_sha: &str,
    reviewer_id: &str,
) -> Result<String, String> {
    let stripped = strip_existing_metadata_block(body, marker);
    let verdict =
        super::detection::extract_verdict_from_comment_body(&stripped).ok_or_else(|| {
            "missing explicit review verdict (PASS|FAIL); set verdict before publishing".to_string()
        })?;
    let metadata = build_generated_metadata_block(
        marker,
        review_type,
        pr_number,
        head_sha,
        reviewer_id,
        &verdict,
    )?;
    let normalized = stripped.trim_end();
    if normalized.is_empty() {
        Ok(format!("{metadata}\n"))
    } else {
        Ok(format!("{normalized}\n\n{metadata}\n"))
    }
}

fn patch_issue_comment_body(owner_repo: &str, comment_id: u64, body: &str) -> Result<(), String> {
    let mut payload_file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("failed to create temp payload for comment patch: {err}"))?;
    let payload = serde_json::json!({ "body": body });
    let payload_text = serde_json::to_string(&payload)
        .map_err(|err| format!("failed to serialize comment patch payload: {err}"))?;
    payload_file
        .write_all(payload_text.as_bytes())
        .map_err(|err| format!("failed to write comment patch payload: {err}"))?;
    payload_file
        .flush()
        .map_err(|err| format!("failed to flush comment patch payload: {err}"))?;

    let endpoint = format!("/repos/{owner_repo}/issues/comments/{comment_id}");
    let output = Command::new("gh")
        .args([
            "api",
            &endpoint,
            "--method",
            "PATCH",
            "--input",
            &payload_file.path().display().to_string(),
        ])
        .output()
        .map_err(|err| format!("failed to execute gh api for comment patch: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed patching comment {comment_id}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{render_comment_with_generated_metadata, review_type_for_marker};
    use crate::commands::fac_review::types::{QUALITY_MARKER, SECURITY_MARKER};

    #[test]
    fn review_type_for_marker_maps_known_markers() {
        assert_eq!(review_type_for_marker(SECURITY_MARKER), Some("security"));
        assert_eq!(review_type_for_marker(QUALITY_MARKER), Some("code-quality"));
        assert_eq!(review_type_for_marker("<!-- unknown -->"), None);
    }

    #[test]
    fn render_comment_with_generated_metadata_appends_block() {
        let body = r"
## Code Quality Review: PASS
### **MINOR FINDINGS**
1. Improve this.
";
        let rendered = render_comment_with_generated_metadata(
            body,
            QUALITY_MARKER,
            "code-quality",
            587,
            "0123456789abcdef0123456789abcdef01234567",
            "fac-bot",
        )
        .expect("rendered");
        assert!(rendered.contains(QUALITY_MARKER));
        assert!(rendered.contains("\"schema\": \"apm2.review.metadata.v1\""));
        assert!(rendered.contains("\"review_type\": \"code-quality\""));
        assert!(rendered.contains("\"pr_number\": 587"));
        assert!(rendered.contains("\"head_sha\": \"0123456789abcdef0123456789abcdef01234567\""));
        assert!(rendered.contains("\"reviewer_id\": \"fac-bot\""));
        assert!(rendered.contains("\"verdict\": \"PASS\""));
        assert!(!rendered.contains("\"severity_counts\""));
    }

    #[test]
    fn render_comment_with_generated_metadata_requires_explicit_verdict() {
        let body = r"
### **MINOR FINDINGS**
1. Improve this.
";
        let err = render_comment_with_generated_metadata(
            body,
            QUALITY_MARKER,
            "code-quality",
            587,
            "0123456789abcdef0123456789abcdef01234567",
            "fac-bot",
        )
        .expect_err("missing verdict should fail");
        assert!(err.contains("missing explicit review verdict"));
    }

    #[test]
    fn render_comment_with_generated_metadata_replaces_existing_block() {
        let body = r#"
## Security Review: PASS

<!-- apm2-review-metadata:v1:security -->
```json
{
  "schema": "apm2.review.metadata.v1",
  "review_type": "security",
  "pr_number": 1,
  "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "verdict": "PASS",
  "severity_counts": { "blocker": 0, "major": 0, "minor": 0, "nit": 0 },
  "reviewer_id": "old"
}
```
"#;
        let rendered = render_comment_with_generated_metadata(
            body,
            SECURITY_MARKER,
            "security",
            441,
            "0123456789abcdef0123456789abcdef01234567",
            "new-reviewer",
        )
        .expect("rendered");
        assert_eq!(rendered.matches(SECURITY_MARKER).count(), 1);
        assert!(rendered.contains("\"pr_number\": 441"));
        assert!(rendered.contains("\"reviewer_id\": \"new-reviewer\""));
        assert!(!rendered.contains("\"head_sha\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""));
        assert!(!rendered.contains("\"severity_counts\""));
    }

    #[test]
    fn render_comment_with_generated_metadata_uses_current_header_not_stale_metadata_verdict() {
        let body = r#"
## Security Review: PASS

<!-- apm2-review-metadata:v1:security -->
```json
{
  "schema": "apm2.review.metadata.v1",
  "review_type": "security",
  "pr_number": 1,
  "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "verdict": "FAIL",
  "reviewer_id": "old"
}
```
"#;
        let rendered = render_comment_with_generated_metadata(
            body,
            SECURITY_MARKER,
            "security",
            441,
            "0123456789abcdef0123456789abcdef01234567",
            "new-reviewer",
        )
        .expect("rendered");
        assert!(rendered.contains("## Security Review: PASS"));
        assert!(rendered.contains("\"verdict\": \"PASS\""));
        assert!(!rendered.contains("\"verdict\": \"FAIL\""));
    }
}
