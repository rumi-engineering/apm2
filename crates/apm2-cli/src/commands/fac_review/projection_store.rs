//! Local authoritative projection storage for FAC review CLI flows.
//!
//! This module provides a local-first state surface under
//! `~/.apm2/fac_projection`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use fs2::FileExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::types::{
    apm2_home_dir, ensure_parent_dir, now_iso8601, sanitize_for_path, validate_expected_head_sha,
};

const PROJECTION_ROOT_DIR: &str = "fac_projection";
const IDENTITY_SCHEMA: &str = "apm2.fac.projection.identity.v1";
const BRANCH_HINT_SCHEMA: &str = "apm2.fac.projection.branch_hint.v1";
const ISSUE_COMMENTS_SCHEMA: &str = "apm2.fac.projection.issue_comments.v1";
const REVIEWER_SCHEMA: &str = "apm2.fac.projection.reviewer.v1";
const PR_BODY_SCHEMA: &str = "apm2.fac.projection.pr_body.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionIdentityRecord {
    pub schema: String,
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree: Option<String>,
    pub source: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectionIdentitySnapshot {
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub branch: Option<String>,
    pub worktree: Option<String>,
    pub source: String,
    pub updated_at: String,
}

impl From<ProjectionIdentityRecord> for ProjectionIdentitySnapshot {
    fn from(value: ProjectionIdentityRecord) -> Self {
        Self {
            owner_repo: value.owner_repo,
            pr_number: value.pr_number,
            head_sha: value.head_sha,
            branch: value.branch,
            worktree: value.worktree,
            source: value.source,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BranchHintRecord {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    branch: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueCommentsCache<T> {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    updated_at: String,
    comments: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewerIdentity {
    schema: String,
    reviewer_id: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrBodySnapshot {
    schema: String,
    body: String,
    source: String,
    updated_at: String,
}

fn projection_root() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join(PROJECTION_ROOT_DIR))
}

fn repo_dir(owner_repo: &str) -> Result<PathBuf, String> {
    Ok(projection_root()?
        .join("repos")
        .join(sanitize_for_path(owner_repo)))
}

fn pr_dir(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(repo_dir(owner_repo)?.join(format!("pr-{pr_number}")))
}

fn sha_dir(owner_repo: &str, pr_number: u32, sha: &str) -> Result<PathBuf, String> {
    Ok(pr_dir(owner_repo, pr_number)?.join(format!("sha-{}", sanitize_for_path(sha))))
}

fn branch_hint_path(owner_repo: &str, branch: &str) -> Result<PathBuf, String> {
    Ok(projection_root()?
        .join("by-branch")
        .join(sanitize_for_path(owner_repo))
        .join(format!("{}.json", sanitize_for_path(branch))))
}

fn identity_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(pr_dir(owner_repo, pr_number)?.join("identity.json"))
}

fn issue_comments_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(pr_dir(owner_repo, pr_number)?.join("issue_comments.json"))
}

fn issue_comments_lock_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(pr_dir(owner_repo, pr_number)?.join("issue_comments.lock"))
}

fn reviewer_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(pr_dir(owner_repo, pr_number)?.join("reviewer.json"))
}

fn pr_body_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(pr_dir(owner_repo, pr_number)?.join("pr_body_snapshot.json"))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create temp file in {}: {err}", parent.display()))?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), value)
        .map_err(|err| format!("failed to serialize {}: {err}", path.display()))?;
    tmp.as_file_mut()
        .flush()
        .map_err(|err| format!("failed to flush {}: {err}", path.display()))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", path.display()))?;
    tmp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

fn read_json_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<T>(&bytes)
            .map(Some)
            .map_err(|err| format!("failed to parse {}: {err}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("failed to read {}: {err}", path.display())),
    }
}

pub(super) fn save_identity(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    branch: Option<&str>,
    worktree: Option<&Path>,
    source: &str,
) -> Result<(), String> {
    validate_expected_head_sha(head_sha)?;
    let head_sha = head_sha.to_ascii_lowercase();

    let record = ProjectionIdentityRecord {
        schema: IDENTITY_SCHEMA.to_string(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        head_sha: head_sha.clone(),
        branch: branch.map(ToString::to_string),
        worktree: worktree.map(|path| path.display().to_string()),
        source: source.to_string(),
        updated_at: now_iso8601(),
    };

    let identity_path = identity_path(owner_repo, pr_number)?;
    write_json_atomic(&identity_path, &record)?;

    let sha_identity_path = sha_dir(owner_repo, pr_number, &head_sha)?.join("identity.json");
    write_json_atomic(&sha_identity_path, &record)?;

    if let Some(branch_name) = branch.filter(|value| !value.is_empty()) {
        let hint = BranchHintRecord {
            schema: BRANCH_HINT_SCHEMA.to_string(),
            owner_repo: owner_repo.to_string(),
            pr_number,
            head_sha,
            branch: branch_name.to_string(),
            updated_at: now_iso8601(),
        };
        let hint_path = branch_hint_path(owner_repo, branch_name)?;
        write_json_atomic(&hint_path, &hint)?;
    }

    Ok(())
}

pub(super) fn save_identity_with_context(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    source: &str,
) -> Result<(), String> {
    let branch = current_branch().ok();
    let worktree = std::env::current_dir().ok();
    save_identity(
        owner_repo,
        pr_number,
        head_sha,
        branch.as_deref(),
        worktree.as_deref(),
        source,
    )
}

pub(super) fn load_pr_identity(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<ProjectionIdentityRecord>, String> {
    read_json_optional(&identity_path(owner_repo, pr_number)?)
}

pub fn load_pr_identity_snapshot(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<ProjectionIdentitySnapshot>, String> {
    Ok(load_pr_identity(owner_repo, pr_number)?.map(ProjectionIdentitySnapshot::from))
}

pub(super) fn load_branch_identity(
    owner_repo: &str,
    branch: &str,
) -> Result<Option<ProjectionIdentityRecord>, String> {
    let Some(hint) =
        read_json_optional::<BranchHintRecord>(&branch_hint_path(owner_repo, branch)?)?
    else {
        return Ok(None);
    };
    load_pr_identity(&hint.owner_repo, hint.pr_number)
}

pub(super) fn save_issue_comments_cache<T: Serialize>(
    owner_repo: &str,
    pr_number: u32,
    comments: &[T],
) -> Result<(), String> {
    let payload = comments
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("failed to serialize issue comment cache payload: {err}"))?;
    let cache = IssueCommentsCache {
        schema: ISSUE_COMMENTS_SCHEMA.to_string(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        updated_at: now_iso8601(),
        comments: payload,
    };
    write_json_atomic(&issue_comments_path(owner_repo, pr_number)?, &cache)
}

pub(super) fn load_issue_comments_cache<T: DeserializeOwned>(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<Vec<T>>, String> {
    let Some(cache) = read_json_optional::<IssueCommentsCache<serde_json::Value>>(
        &issue_comments_path(owner_repo, pr_number)?,
    )?
    else {
        return Ok(None);
    };
    let parsed = cache
        .comments
        .into_iter()
        .map(|value| serde_json::from_value::<T>(value).map_err(|err| err.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("failed to decode cached issue comments: {err}"))?;
    Ok(Some(parsed))
}

pub(super) fn upsert_issue_comment_cache_entry(
    owner_repo: &str,
    pr_number: u32,
    comment_id: u64,
    html_url: &str,
    body: &str,
    reviewer_login: &str,
) -> Result<(), String> {
    let lock_path = issue_comments_lock_path(owner_repo, pr_number)?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open issue comment cache lock {}: {err}",
                lock_path.display()
            )
        })?;
    lock_file.lock_exclusive().map_err(|err| {
        format!(
            "failed to acquire issue comment cache lock {}: {err}",
            lock_path.display()
        )
    })?;

    let mut comments =
        load_issue_comments_cache::<serde_json::Value>(owner_repo, pr_number)?.unwrap_or_default();
    let entry = serde_json::json!({
        "id": comment_id,
        "body": body,
        "html_url": html_url,
        "created_at": now_iso8601(),
        "user": { "login": reviewer_login },
    });

    if let Some(existing) = comments
        .iter_mut()
        .find(|value| value.get("id").and_then(serde_json::Value::as_u64) == Some(comment_id))
    {
        *existing = entry;
    } else {
        comments.push(entry);
    }

    let write_result = save_issue_comments_cache(owner_repo, pr_number, &comments);
    drop(lock_file);
    write_result
}

pub(super) fn save_trusted_reviewer_id(
    owner_repo: &str,
    pr_number: u32,
    reviewer_id: &str,
) -> Result<(), String> {
    let payload = ReviewerIdentity {
        schema: REVIEWER_SCHEMA.to_string(),
        reviewer_id: reviewer_id.to_string(),
        updated_at: now_iso8601(),
    };
    write_json_atomic(&reviewer_path(owner_repo, pr_number)?, &payload)
}

pub(super) fn load_trusted_reviewer_id(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<String>, String> {
    let Some(payload) =
        read_json_optional::<ReviewerIdentity>(&reviewer_path(owner_repo, pr_number)?)?
    else {
        return Ok(None);
    };
    if payload.reviewer_id.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(payload.reviewer_id))
}

pub(super) fn save_pr_body_snapshot(
    owner_repo: &str,
    pr_number: u32,
    body: &str,
    source: &str,
) -> Result<(), String> {
    let payload = PrBodySnapshot {
        schema: PR_BODY_SCHEMA.to_string(),
        body: body.to_string(),
        source: source.to_string(),
        updated_at: now_iso8601(),
    };
    write_json_atomic(&pr_body_path(owner_repo, pr_number)?, &payload)
}

pub(super) fn load_pr_body_snapshot(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<String>, String> {
    let Some(payload) =
        read_json_optional::<PrBodySnapshot>(&pr_body_path(owner_repo, pr_number)?)?
    else {
        return Ok(None);
    };
    Ok(Some(payload.body))
}

fn current_branch() -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .map_err(|err| format!("failed to resolve current branch: {err}"))?;
    if !output.status.success() {
        return Err("git rev-parse --abbrev-ref HEAD failed".to_string());
    }
    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if branch.is_empty() || branch == "HEAD" {
        return Err("current branch is detached HEAD".to_string());
    }
    Ok(branch)
}
