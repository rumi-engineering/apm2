//! Local authoritative projection storage for FAC review CLI flows.
//!
//! This module provides a local-first state surface under
//! `~/.apm2/fac_projection`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use apm2_core::fac::{parse_b3_256_digest, parse_policy_hash};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::types::{
    apm2_home_dir, ensure_parent_dir, now_iso8601, now_iso8601_millis, sanitize_for_path,
    validate_expected_head_sha,
};

const PROJECTION_ROOT_DIR: &str = "fac_projection";
const IDENTITY_SCHEMA: &str = "apm2.fac.projection.identity.v1";
const BRANCH_HINT_SCHEMA: &str = "apm2.fac.projection.branch_hint.v1";
const REVIEWER_SCHEMA: &str = "apm2.fac.projection.reviewer.v1";
const PR_BODY_SCHEMA: &str = "apm2.fac.projection.pr_body.v1";
const PREPARE_BASE_SNAPSHOT_SCHEMA: &str = "apm2.fac.projection.prepare_base_snapshot.v1";
const GATES_ADMISSION_SCHEMA: &str = "apm2.fac.projection.gates_admission.v1";
const VERDICT_PROJECTION_PENDING_SCHEMA: &str = "apm2.fac.projection.verdict_projection_pending.v1";
const MERGE_PROJECTION_PENDING_SCHEMA: &str = "apm2.fac.projection.merge_projection_pending.v1";
const SHA256_HEX_LEN: usize = 64;
const MAX_IDENTITY_HEAD_SCAN_PR_DIRS: usize = 4096;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareBaseSnapshotRecord {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    base_sha: String,
    source: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatesAdmissionRecord {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    gate_job_id: String,
    gate_receipt_id: String,
    policy_hash: String,
    gate_evidence_hashes: Vec<String>,
    source: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictProjectionPendingRecord {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    dimension: String,
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend_id: Option<String>,
    last_error: String,
    attempt_count: u32,
    source: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MergeProjectionPendingRecord {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    merge_sha: String,
    source_branch: String,
    merge_receipt_hash: String,
    merged_at_iso: String,
    gate_job_id: String,
    gate_receipt_id: String,
    policy_hash: String,
    gate_evidence_hashes: Vec<String>,
    verdict_hashes: Vec<String>,
    last_error: String,
    attempt_count: u32,
    source: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct GatesAdmissionSnapshot {
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub gate_job_id: String,
    pub gate_receipt_id: String,
    pub policy_hash: String,
    pub gate_evidence_hashes: Vec<String>,
    pub source: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct PrepareBaseSnapshot {
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub base_sha: String,
    pub source: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct MergeProjectionPendingSnapshot {
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub merge_sha: String,
    pub source_branch: String,
    pub merge_receipt_hash: String,
    pub merged_at_iso: String,
    pub gate_job_id: String,
    pub gate_receipt_id: String,
    pub policy_hash: String,
    pub gate_evidence_hashes: Vec<String>,
    pub verdict_hashes: Vec<String>,
    pub last_error: String,
    pub attempt_count: u32,
    pub source: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct VerdictProjectionPendingSnapshot {
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub dimension: String,
    pub decision: String,
    pub reason: Option<String>,
    pub model_id: Option<String>,
    pub backend_id: Option<String>,
    pub last_error: String,
    pub attempt_count: u32,
    pub source: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub(super) struct GatesAdmissionSaveRequest<'a> {
    pub gate_job_id: &'a str,
    pub gate_receipt_id: &'a str,
    pub policy_hash: &'a str,
    pub gate_evidence_hashes: &'a [String],
    pub source: &'a str,
}

#[derive(Debug, Clone)]
pub(super) struct MergeProjectionPendingSaveRequest<'a> {
    pub merge_sha: &'a str,
    pub source_branch: &'a str,
    pub merge_receipt_hash: &'a str,
    pub merged_at_iso: &'a str,
    pub gate_job_id: &'a str,
    pub gate_receipt_id: &'a str,
    pub policy_hash: &'a str,
    pub gate_evidence_hashes: &'a [String],
    pub verdict_hashes: &'a [String],
    pub last_error: &'a str,
    pub attempt_count: u32,
    pub source: &'a str,
}

#[derive(Debug, Clone)]
pub(super) struct VerdictProjectionPendingSaveRequest<'a> {
    pub dimension: &'a str,
    pub decision: &'a str,
    pub reason: Option<&'a str>,
    pub model_id: Option<&'a str>,
    pub backend_id: Option<&'a str>,
    pub last_error: &'a str,
    pub attempt_count: u32,
    pub source: &'a str,
}

impl From<GatesAdmissionRecord> for GatesAdmissionSnapshot {
    fn from(value: GatesAdmissionRecord) -> Self {
        Self {
            owner_repo: value.owner_repo,
            pr_number: value.pr_number,
            head_sha: value.head_sha,
            gate_job_id: value.gate_job_id,
            gate_receipt_id: value.gate_receipt_id,
            policy_hash: value.policy_hash,
            gate_evidence_hashes: value.gate_evidence_hashes,
            source: value.source,
            updated_at: value.updated_at,
        }
    }
}

impl From<PrepareBaseSnapshotRecord> for PrepareBaseSnapshot {
    fn from(value: PrepareBaseSnapshotRecord) -> Self {
        Self {
            owner_repo: value.owner_repo,
            pr_number: value.pr_number,
            head_sha: value.head_sha,
            base_sha: value.base_sha,
            source: value.source,
            updated_at: value.updated_at,
        }
    }
}

impl From<VerdictProjectionPendingRecord> for VerdictProjectionPendingSnapshot {
    fn from(value: VerdictProjectionPendingRecord) -> Self {
        Self {
            owner_repo: value.owner_repo,
            pr_number: value.pr_number,
            head_sha: value.head_sha,
            dimension: value.dimension,
            decision: value.decision,
            reason: value.reason,
            model_id: value.model_id,
            backend_id: value.backend_id,
            last_error: value.last_error,
            attempt_count: value.attempt_count,
            source: value.source,
            updated_at: value.updated_at,
        }
    }
}

impl From<MergeProjectionPendingRecord> for MergeProjectionPendingSnapshot {
    fn from(value: MergeProjectionPendingRecord) -> Self {
        Self {
            owner_repo: value.owner_repo,
            pr_number: value.pr_number,
            head_sha: value.head_sha,
            merge_sha: value.merge_sha,
            source_branch: value.source_branch,
            merge_receipt_hash: value.merge_receipt_hash,
            merged_at_iso: value.merged_at_iso,
            gate_job_id: value.gate_job_id,
            gate_receipt_id: value.gate_receipt_id,
            policy_hash: value.policy_hash,
            gate_evidence_hashes: value.gate_evidence_hashes,
            verdict_hashes: value.verdict_hashes,
            last_error: value.last_error,
            attempt_count: value.attempt_count,
            source: value.source,
            updated_at: value.updated_at,
        }
    }
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

fn reviewer_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(pr_dir(owner_repo, pr_number)?.join("reviewer.json"))
}

fn pr_body_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(pr_dir(owner_repo, pr_number)?.join("pr_body_snapshot.json"))
}

fn prepare_base_snapshot_path(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<PathBuf, String> {
    Ok(sha_dir(owner_repo, pr_number, head_sha)?.join("prepare_base_snapshot.json"))
}

fn gates_admission_path(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<PathBuf, String> {
    Ok(sha_dir(owner_repo, pr_number, head_sha)?.join("gates_admission.json"))
}

fn merge_projection_pending_path(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<PathBuf, String> {
    Ok(sha_dir(owner_repo, pr_number, head_sha)?.join("merge_projection_pending.json"))
}

fn legacy_verdict_projection_pending_path(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<PathBuf, String> {
    Ok(sha_dir(owner_repo, pr_number, head_sha)?.join("verdict_projection_pending.json"))
}

fn verdict_projection_pending_path(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
) -> Result<PathBuf, String> {
    let normalized = dimension.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("verdict projection pending path requires non-empty dimension".to_string());
    }
    Ok(sha_dir(owner_repo, pr_number, head_sha)?.join(format!(
        "verdict_projection_pending.{}.json",
        sanitize_for_path(&normalized)
    )))
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

fn normalize_b3_digest(value: &str, field: &str) -> Result<String, String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(format!("{field} requires non-empty b3-256 digest"));
    }
    if parse_b3_256_digest(normalized).is_none() {
        return Err(format!(
            "{field} requires b3-256 digest (invalid value `{normalized}`)"
        ));
    }
    Ok(normalized.to_string())
}

fn normalize_policy_hash(value: &str, field: &str) -> Result<String, String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(format!("{field} requires non-empty policy_hash"));
    }
    if parse_policy_hash(normalized).is_none() {
        return Err(format!(
            "{field} requires b3-256 policy_hash (invalid value `{normalized}`)"
        ));
    }
    Ok(normalized.to_string())
}

fn normalize_b3_digest_list(values: &[String], field: &str) -> Result<Vec<String>, String> {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        normalized.push(normalize_b3_digest(value, field)?);
    }
    normalized.sort();
    normalized.dedup();
    if normalized.is_empty() {
        return Err(format!("{field} requires at least one digest"));
    }
    Ok(normalized)
}

fn normalize_sha256_hex_list(values: &[String], field: &str) -> Result<Vec<String>, String> {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let digest = trimmed.to_ascii_lowercase();
        if digest.len() != SHA256_HEX_LEN || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "{field} requires 64-char hex digests (invalid value `{trimmed}`)"
            ));
        }
        normalized.push(digest);
    }
    normalized.sort();
    normalized.dedup();
    if normalized.is_empty() {
        return Err(format!("{field} requires at least one digest"));
    }
    Ok(normalized)
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

pub(super) fn load_pr_identity_by_head_sha(
    owner_repo: &str,
    head_sha: &str,
) -> Result<Option<ProjectionIdentityRecord>, String> {
    validate_expected_head_sha(head_sha)?;
    let normalized_head_sha = head_sha.to_ascii_lowercase();
    let repo_path = repo_dir(owner_repo)?;
    let entries = match fs::read_dir(&repo_path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to list projection repo directory {}: {err}",
                repo_path.display()
            ));
        },
    };

    let mut scanned_pr_dirs: usize = 0;
    let mut matched: Option<ProjectionIdentityRecord> = None;
    for entry in entries {
        scanned_pr_dirs = scanned_pr_dirs.saturating_add(1);
        if scanned_pr_dirs > MAX_IDENTITY_HEAD_SCAN_PR_DIRS {
            return Err(format!(
                "head-sha identity scan exceeded directory cap ({MAX_IDENTITY_HEAD_SCAN_PR_DIRS}) for repo `{owner_repo}`"
            ));
        }
        let entry =
            entry.map_err(|err| format!("failed to enumerate PR projection directory: {err}"))?;
        let file_type = entry
            .file_type()
            .map_err(|err| format!("failed to read projection entry type: {err}"))?;
        if !file_type.is_dir() {
            continue;
        }
        let Some(pr_number) = entry
            .file_name()
            .to_string_lossy()
            .strip_prefix("pr-")
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let candidate_path =
            sha_dir(owner_repo, pr_number, &normalized_head_sha)?.join("identity.json");
        let Some(identity) = read_json_optional::<ProjectionIdentityRecord>(&candidate_path)?
        else {
            continue;
        };
        if !identity.owner_repo.eq_ignore_ascii_case(owner_repo)
            || identity.pr_number != pr_number
            || !identity.head_sha.eq_ignore_ascii_case(&normalized_head_sha)
        {
            return Err(format!(
                "invalid projection identity at {} for repo `{owner_repo}` and head `{normalized_head_sha}`",
                candidate_path.display()
            ));
        }
        if let Some(existing) = matched.as_ref()
            && existing.pr_number != identity.pr_number
        {
            return Err(format!(
                "ambiguous projection identity for repo `{owner_repo}` and head `{normalized_head_sha}`: PR #{} and PR #{}",
                existing.pr_number, identity.pr_number
            ));
        }
        matched = Some(identity);
    }
    Ok(matched)
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

pub(super) fn save_prepare_base_snapshot(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    base_sha: &str,
    source: &str,
) -> Result<(), String> {
    validate_expected_head_sha(head_sha)?;
    validate_expected_head_sha(base_sha)?;
    let source = source.trim();
    if source.is_empty() {
        return Err("prepare base snapshot requires non-empty source".to_string());
    }

    let normalized_head = head_sha.to_ascii_lowercase();
    let normalized_base = base_sha.to_ascii_lowercase();
    let record = PrepareBaseSnapshotRecord {
        schema: PREPARE_BASE_SNAPSHOT_SCHEMA.to_string(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        head_sha: normalized_head.clone(),
        base_sha: normalized_base,
        source: source.to_string(),
        updated_at: now_iso8601(),
    };
    write_json_atomic(
        &prepare_base_snapshot_path(owner_repo, pr_number, &normalized_head)?,
        &record,
    )
}

pub(super) fn load_prepare_base_snapshot(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<Option<PrepareBaseSnapshot>, String> {
    validate_expected_head_sha(head_sha)?;
    let normalized_head = head_sha.to_ascii_lowercase();
    let Some(record) = read_json_optional::<PrepareBaseSnapshotRecord>(
        &prepare_base_snapshot_path(owner_repo, pr_number, &normalized_head)?,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(record.into()))
}

pub(super) fn save_gates_admission(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    request: &GatesAdmissionSaveRequest<'_>,
) -> Result<(), String> {
    validate_expected_head_sha(head_sha)?;
    let head_sha = head_sha.to_ascii_lowercase();
    let gate_job_id = request.gate_job_id.trim();
    if gate_job_id.is_empty() {
        return Err("gate admission requires non-empty gate_job_id".to_string());
    }
    let gate_receipt_id = request.gate_receipt_id.trim();
    if gate_receipt_id.is_empty() {
        return Err("gate admission requires non-empty gate_receipt_id".to_string());
    }
    let policy_hash = normalize_policy_hash(request.policy_hash, "gate admission")?;
    let hashes =
        normalize_b3_digest_list(request.gate_evidence_hashes, "gate admission gate hashes")?;
    let record = GatesAdmissionRecord {
        schema: GATES_ADMISSION_SCHEMA.to_string(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        head_sha: head_sha.clone(),
        gate_job_id: gate_job_id.to_string(),
        gate_receipt_id: gate_receipt_id.to_string(),
        policy_hash,
        gate_evidence_hashes: hashes,
        source: request.source.to_string(),
        updated_at: now_iso8601(),
    };
    write_json_atomic(
        &gates_admission_path(owner_repo, pr_number, &head_sha)?,
        &record,
    )
}

pub(super) fn load_gates_admission(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<Option<GatesAdmissionSnapshot>, String> {
    validate_expected_head_sha(head_sha)?;
    let normalized = head_sha.to_ascii_lowercase();
    let Some(record) = read_json_optional::<GatesAdmissionRecord>(&gates_admission_path(
        owner_repo,
        pr_number,
        &normalized,
    )?)?
    else {
        return Ok(None);
    };
    Ok(Some(record.into()))
}

pub(super) fn save_verdict_projection_pending(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    request: &VerdictProjectionPendingSaveRequest<'_>,
) -> Result<(), String> {
    validate_expected_head_sha(head_sha)?;
    let head_sha = head_sha.to_ascii_lowercase();

    let dimension = request.dimension.trim().to_ascii_lowercase();
    if dimension.is_empty() {
        return Err("verdict projection pending record requires non-empty dimension".to_string());
    }
    let decision = request.decision.trim().to_ascii_lowercase();
    if !matches!(decision.as_str(), "approve" | "deny") {
        return Err(format!(
            "verdict projection pending record requires decision approve|deny (got `{}`)",
            request.decision
        ));
    }
    let source = request.source.trim();
    if source.is_empty() {
        return Err("verdict projection pending record requires non-empty source".to_string());
    }
    let last_error = request.last_error.trim();
    if last_error.is_empty() {
        return Err("verdict projection pending record requires non-empty last_error".to_string());
    }

    let normalize_optional = |value: Option<&str>| -> Option<String> {
        value
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string)
    };
    let path = verdict_projection_pending_path(owner_repo, pr_number, &head_sha, &dimension)?;
    let existing_attempt = read_json_optional::<VerdictProjectionPendingRecord>(&path)?
        .map_or(0, |record| record.attempt_count);
    let requested_attempt = request.attempt_count.max(1);
    let attempt_count = if requested_attempt <= existing_attempt {
        existing_attempt.saturating_add(1)
    } else {
        requested_attempt
    };

    let record = VerdictProjectionPendingRecord {
        schema: VERDICT_PROJECTION_PENDING_SCHEMA.to_string(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        head_sha,
        dimension,
        decision,
        reason: normalize_optional(request.reason),
        model_id: normalize_optional(request.model_id),
        backend_id: normalize_optional(request.backend_id),
        last_error: last_error.to_string(),
        attempt_count,
        source: source.to_string(),
        updated_at: now_iso8601_millis(),
    };
    write_json_atomic(&path, &record)
}
#[cfg(test)]
pub(super) fn load_verdict_projection_pending(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
) -> Result<Option<VerdictProjectionPendingSnapshot>, String> {
    validate_expected_head_sha(head_sha)?;
    let normalized_dimension = dimension.trim().to_ascii_lowercase();
    if normalized_dimension.is_empty() {
        return Err("load verdict projection pending requires non-empty dimension".to_string());
    }
    let normalized = head_sha.to_ascii_lowercase();
    if let Some(record) =
        read_json_optional::<VerdictProjectionPendingRecord>(&verdict_projection_pending_path(
            owner_repo,
            pr_number,
            &normalized,
            &normalized_dimension,
        )?)?
    {
        return Ok(Some(record.into()));
    }
    let Some(record) = read_json_optional::<VerdictProjectionPendingRecord>(
        &legacy_verdict_projection_pending_path(owner_repo, pr_number, &normalized)?,
    )?
    else {
        return Ok(None);
    };
    if !record.dimension.eq_ignore_ascii_case(&normalized_dimension) {
        return Ok(None);
    }
    Ok(Some(record.into()))
}

pub(super) fn clear_verdict_projection_pending(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
) -> Result<(), String> {
    validate_expected_head_sha(head_sha)?;
    let normalized_sha = head_sha.to_ascii_lowercase();
    let normalized_dimension = dimension.trim().to_ascii_lowercase();
    if normalized_dimension.is_empty() {
        return Err("clear verdict projection pending requires non-empty dimension".to_string());
    }

    let mut failures = Vec::new();
    let current_path = verdict_projection_pending_path(
        owner_repo,
        pr_number,
        &normalized_sha,
        &normalized_dimension,
    )?;
    match fs::remove_file(&current_path) {
        Ok(()) => {},
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {},
        Err(err) => failures.push(format!(
            "failed to remove {}: {err}",
            current_path.display()
        )),
    }

    // Clean up legacy pending path if it matches this dimension.
    let legacy_path =
        legacy_verdict_projection_pending_path(owner_repo, pr_number, &normalized_sha)?;
    if let Some(record) = read_json_optional::<VerdictProjectionPendingRecord>(&legacy_path)?
        && record.dimension.eq_ignore_ascii_case(&normalized_dimension)
    {
        match fs::remove_file(&legacy_path) {
            Ok(()) => {},
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {},
            Err(err) => failures.push(format!("failed to remove {}: {err}", legacy_path.display())),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

pub(super) fn list_verdict_projection_pending_for_repo(
    owner_repo: &str,
    limit: usize,
) -> Result<Vec<VerdictProjectionPendingSnapshot>, String> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let repo_path = repo_dir(owner_repo)?;
    let entries = match fs::read_dir(&repo_path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(format!(
                "failed to list projection repo directory {}: {err}",
                repo_path.display()
            ));
        },
    };

    let mut pending = Vec::new();
    for pr_entry in entries {
        let pr_entry = pr_entry
            .map_err(|err| format!("failed to enumerate PR projection directory: {err}"))?;
        let pr_type = pr_entry
            .file_type()
            .map_err(|err| format!("failed to read projection entry type: {err}"))?;
        if !pr_type.is_dir() {
            continue;
        }
        let sha_entries = match fs::read_dir(pr_entry.path()) {
            Ok(value) => value,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "failed to list SHA projection directory {}: {err}",
                    pr_entry.path().display()
                ));
            },
        };
        for sha_entry in sha_entries {
            let sha_entry = sha_entry
                .map_err(|err| format!("failed to enumerate SHA projection directory: {err}"))?;
            let sha_type = sha_entry
                .file_type()
                .map_err(|err| format!("failed to read SHA projection entry type: {err}"))?;
            if !sha_type.is_dir() {
                continue;
            }
            let files = match fs::read_dir(sha_entry.path()) {
                Ok(value) => value,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(format!(
                        "failed to list pending projection files in {}: {err}",
                        sha_entry.path().display()
                    ));
                },
            };
            for pending_file in files {
                let pending_file = pending_file.map_err(|err| {
                    format!("failed to enumerate pending projection file entry: {err}")
                })?;
                let file_type = pending_file
                    .file_type()
                    .map_err(|err| format!("failed to read pending projection file type: {err}"))?;
                if !file_type.is_file() {
                    continue;
                }
                let file_name = pending_file.file_name();
                let file_name = file_name.to_string_lossy();
                if !file_name.starts_with("verdict_projection_pending")
                    || !file_name.ends_with(".json")
                {
                    continue;
                }
                let path = pending_file.path();
                let Some(record) = read_json_optional::<VerdictProjectionPendingRecord>(&path)?
                else {
                    continue;
                };
                pending.push(VerdictProjectionPendingSnapshot::from(record));
            }
        }
    }
    pending.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    pending.truncate(limit);
    Ok(pending)
}

pub(super) fn save_merge_projection_pending(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    request: &MergeProjectionPendingSaveRequest<'_>,
) -> Result<(), String> {
    validate_expected_head_sha(head_sha)?;
    validate_expected_head_sha(request.merge_sha)?;
    let head_sha = head_sha.to_ascii_lowercase();
    let merge_sha = request.merge_sha.to_ascii_lowercase();
    let source_branch = request.source_branch.trim();
    if source_branch.is_empty() {
        return Err("merge projection pending record requires non-empty source_branch".to_string());
    }
    let merge_receipt_hash = normalize_b3_digest(
        request.merge_receipt_hash,
        "merge projection pending receipt hash",
    )?;
    let gate_job_id = request.gate_job_id.trim();
    if gate_job_id.is_empty() {
        return Err("merge projection pending record requires non-empty gate_job_id".to_string());
    }
    let gate_receipt_id = request.gate_receipt_id.trim();
    if gate_receipt_id.is_empty() {
        return Err(
            "merge projection pending record requires non-empty gate_receipt_id".to_string(),
        );
    }
    let policy_hash =
        normalize_policy_hash(request.policy_hash, "merge projection pending policy hash")?;
    let merged_at_iso = request.merged_at_iso.trim();
    if merged_at_iso.is_empty() {
        return Err("merge projection pending record requires non-empty merged_at_iso".to_string());
    }
    let source = request.source.trim();
    if source.is_empty() {
        return Err("merge projection pending record requires non-empty source".to_string());
    }
    let last_error = request.last_error.trim();
    if last_error.is_empty() {
        return Err("merge projection pending record requires non-empty last_error".to_string());
    }
    let gate_hashes = normalize_b3_digest_list(
        request.gate_evidence_hashes,
        "merge projection pending gate hashes",
    )?;
    let verdict_hashes = normalize_sha256_hex_list(
        request.verdict_hashes,
        "merge projection pending verdict hashes",
    )?;
    let record = MergeProjectionPendingRecord {
        schema: MERGE_PROJECTION_PENDING_SCHEMA.to_string(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        head_sha: head_sha.clone(),
        merge_sha,
        source_branch: source_branch.to_string(),
        merge_receipt_hash,
        merged_at_iso: merged_at_iso.to_string(),
        gate_job_id: gate_job_id.to_string(),
        gate_receipt_id: gate_receipt_id.to_string(),
        policy_hash,
        gate_evidence_hashes: gate_hashes,
        verdict_hashes,
        last_error: last_error.to_string(),
        attempt_count: request.attempt_count,
        source: source.to_string(),
        updated_at: now_iso8601_millis(),
    };
    write_json_atomic(
        &merge_projection_pending_path(owner_repo, pr_number, &head_sha)?,
        &record,
    )
}
#[cfg(test)]
pub(super) fn load_merge_projection_pending(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<Option<MergeProjectionPendingSnapshot>, String> {
    validate_expected_head_sha(head_sha)?;
    let normalized = head_sha.to_ascii_lowercase();
    let Some(record) = read_json_optional::<MergeProjectionPendingRecord>(
        &merge_projection_pending_path(owner_repo, pr_number, &normalized)?,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(record.into()))
}

pub(super) fn clear_merge_projection_pending(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<(), String> {
    validate_expected_head_sha(head_sha)?;
    let path =
        merge_projection_pending_path(owner_repo, pr_number, &head_sha.to_ascii_lowercase())?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to remove {}: {err}", path.display())),
    }
}

pub(super) fn list_merge_projection_pending_for_repo(
    owner_repo: &str,
    limit: usize,
) -> Result<Vec<MergeProjectionPendingSnapshot>, String> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let repo_path = repo_dir(owner_repo)?;
    let entries = match fs::read_dir(&repo_path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(format!(
                "failed to list projection repo directory {}: {err}",
                repo_path.display()
            ));
        },
    };

    let mut pending = Vec::new();
    for pr_entry in entries {
        let pr_entry = pr_entry
            .map_err(|err| format!("failed to enumerate PR projection directory: {err}"))?;
        let pr_type = pr_entry
            .file_type()
            .map_err(|err| format!("failed to read projection entry type: {err}"))?;
        if !pr_type.is_dir() {
            continue;
        }
        let sha_entries = match fs::read_dir(pr_entry.path()) {
            Ok(value) => value,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "failed to list SHA projection directory {}: {err}",
                    pr_entry.path().display()
                ));
            },
        };
        for sha_entry in sha_entries {
            let sha_entry = sha_entry
                .map_err(|err| format!("failed to enumerate SHA projection directory: {err}"))?;
            let sha_type = sha_entry
                .file_type()
                .map_err(|err| format!("failed to read SHA projection entry type: {err}"))?;
            if !sha_type.is_dir() {
                continue;
            }
            let path = sha_entry.path().join("merge_projection_pending.json");
            let Some(record) = read_json_optional::<MergeProjectionPendingRecord>(&path)? else {
                continue;
            };
            pending.push(MergeProjectionPendingSnapshot::from(record));
        }
    }
    pending.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    pending.truncate(limit);
    Ok(pending)
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

#[cfg(test)]
mod tests {
    use super::{
        GatesAdmissionSaveRequest, MergeProjectionPendingSaveRequest,
        VerdictProjectionPendingSaveRequest, clear_merge_projection_pending,
        clear_verdict_projection_pending, list_merge_projection_pending_for_repo,
        list_verdict_projection_pending_for_repo, load_gates_admission,
        load_merge_projection_pending, load_pr_identity_by_head_sha, load_prepare_base_snapshot,
        load_verdict_projection_pending, save_gates_admission, save_identity,
        save_merge_projection_pending, save_prepare_base_snapshot, save_verdict_projection_pending,
    };

    fn unique_repo(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("example/{tag}-{nanos}")
    }

    #[test]
    fn gates_admission_round_trip() {
        let owner_repo = unique_repo("gates-admission");
        let pr_number = 9;
        let head_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let gate_hashes = vec![format!("b3-256:{}", "11".repeat(32))];
        save_gates_admission(
            &owner_repo,
            pr_number,
            head_sha,
            &GatesAdmissionSaveRequest {
                gate_job_id: "job-1",
                gate_receipt_id: "receipt-1",
                policy_hash: &format!("b3-256:{}", "22".repeat(32)),
                gate_evidence_hashes: &gate_hashes,
                source: "test",
            },
        )
        .expect("save gate admission");

        let loaded = load_gates_admission(&owner_repo, pr_number, head_sha)
            .expect("load gate admission")
            .expect("gate admission exists");
        assert_eq!(loaded.gate_job_id, "job-1");
        assert_eq!(loaded.gate_receipt_id, "receipt-1");
        assert_eq!(loaded.gate_evidence_hashes.len(), 1);
    }

    #[test]
    fn gates_admission_rejects_invalid_hash_material() {
        let owner_repo = unique_repo("gates-admission-invalid");
        let pr_number = 10;
        let head_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let err = save_gates_admission(
            &owner_repo,
            pr_number,
            head_sha,
            &GatesAdmissionSaveRequest {
                gate_job_id: "job-2",
                gate_receipt_id: "receipt-2",
                policy_hash: "not-a-hash",
                gate_evidence_hashes: &[format!("b3-256:{}", "11".repeat(32))],
                source: "test",
            },
        )
        .expect_err("invalid policy hash must fail");
        assert!(err.contains("policy_hash"));

        let err = save_gates_admission(
            &owner_repo,
            pr_number,
            head_sha,
            &GatesAdmissionSaveRequest {
                gate_job_id: "job-2",
                gate_receipt_id: "receipt-2",
                policy_hash: &format!("b3-256:{}", "22".repeat(32)),
                gate_evidence_hashes: &[String::new()],
                source: "test",
            },
        )
        .expect_err("empty gate evidence hashes must fail");
        assert!(err.contains("b3-256 digest"));
    }

    #[test]
    fn prepare_base_snapshot_round_trip() {
        let owner_repo = unique_repo("prepare-base");
        let pr_number = 61;
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let base_sha = "89abcdef0123456789abcdef0123456789abcdef";
        save_prepare_base_snapshot(
            &owner_repo,
            pr_number,
            head_sha,
            base_sha,
            "push_pr_base_api",
        )
        .expect("save prepare base snapshot");

        let loaded = load_prepare_base_snapshot(&owner_repo, pr_number, head_sha)
            .expect("load prepare base snapshot")
            .expect("prepare base snapshot exists");
        assert_eq!(loaded.owner_repo, owner_repo);
        assert_eq!(loaded.pr_number, pr_number);
        assert_eq!(loaded.head_sha, head_sha);
        assert_eq!(loaded.base_sha, base_sha);
        assert_eq!(loaded.source, "push_pr_base_api");
    }

    #[test]
    fn prepare_base_snapshot_rejects_invalid_sha_values() {
        let owner_repo = unique_repo("prepare-base-invalid");
        let pr_number = 62;
        let err = save_prepare_base_snapshot(
            &owner_repo,
            pr_number,
            "not-a-sha",
            "89abcdef0123456789abcdef0123456789abcdef",
            "push_pr_base_api",
        )
        .expect_err("invalid head sha must fail");
        assert!(!err.is_empty());

        let err = save_prepare_base_snapshot(
            &owner_repo,
            pr_number,
            "0123456789abcdef0123456789abcdef01234567",
            "not-a-sha",
            "push_pr_base_api",
        )
        .expect_err("invalid base sha must fail");
        assert!(!err.is_empty());
    }

    #[test]
    fn verdict_projection_pending_round_trip_and_clear() {
        let owner_repo = unique_repo("verdict-pending");
        let pr_number = 71;
        let head_sha = "1111111111111111111111111111111111111111";
        save_verdict_projection_pending(
            &owner_repo,
            pr_number,
            head_sha,
            &VerdictProjectionPendingSaveRequest {
                dimension: "security",
                decision: "approve",
                reason: Some("looks good"),
                model_id: Some("gpt-5"),
                backend_id: Some("openai"),
                last_error: "projection deferred",
                attempt_count: 1,
                source: "verdict_set",
            },
        )
        .expect("save verdict projection pending");

        let loaded = load_verdict_projection_pending(&owner_repo, pr_number, head_sha, "security")
            .expect("load verdict projection pending")
            .expect("verdict projection pending exists");
        assert_eq!(loaded.dimension, "security");
        assert_eq!(loaded.decision, "approve");
        assert_eq!(loaded.reason.as_deref(), Some("looks good"));
        assert_eq!(loaded.attempt_count, 1);

        clear_verdict_projection_pending(&owner_repo, pr_number, head_sha, "security")
            .expect("clear verdict projection pending");
        let reloaded =
            load_verdict_projection_pending(&owner_repo, pr_number, head_sha, "security")
                .expect("reload verdict projection pending");
        assert!(reloaded.is_none());
    }

    #[test]
    fn verdict_projection_pending_rejects_invalid_decision() {
        let owner_repo = unique_repo("verdict-pending-invalid");
        let pr_number = 72;
        let head_sha = "2222222222222222222222222222222222222222";
        let err = save_verdict_projection_pending(
            &owner_repo,
            pr_number,
            head_sha,
            &VerdictProjectionPendingSaveRequest {
                dimension: "security",
                decision: "maybe",
                reason: None,
                model_id: None,
                backend_id: None,
                last_error: "projection deferred",
                attempt_count: 1,
                source: "verdict_set",
            },
        )
        .expect_err("invalid decision must fail");
        assert!(err.contains("approve|deny"));
    }

    #[test]
    fn list_verdict_projection_pending_for_repo_returns_saved_records() {
        let owner_repo = unique_repo("verdict-pending-list");
        let first_sha = "3333333333333333333333333333333333333333";
        let second_sha = "4444444444444444444444444444444444444444";

        save_verdict_projection_pending(
            &owner_repo,
            80,
            first_sha,
            &VerdictProjectionPendingSaveRequest {
                dimension: "security",
                decision: "approve",
                reason: None,
                model_id: None,
                backend_id: None,
                last_error: "network timeout",
                attempt_count: 1,
                source: "verdict_set",
            },
        )
        .expect("save first verdict pending");
        save_verdict_projection_pending(
            &owner_repo,
            81,
            second_sha,
            &VerdictProjectionPendingSaveRequest {
                dimension: "quality",
                decision: "deny",
                reason: Some("issue"),
                model_id: None,
                backend_id: None,
                last_error: "network timeout",
                attempt_count: 2,
                source: "verdict_set",
            },
        )
        .expect("save second verdict pending");

        let listed = list_verdict_projection_pending_for_repo(&owner_repo, 8)
            .expect("list verdict projection pending");
        assert!(listed.len() >= 2);
        assert!(listed.iter().any(|entry| entry.pr_number == 80));
        assert!(listed.iter().any(|entry| entry.pr_number == 81));
    }

    #[test]
    fn merge_projection_pending_round_trip_and_clear() {
        let owner_repo = unique_repo("merge-pending");
        let pr_number = 42;
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let gate_hashes = vec![format!("b3-256:{}", "aa".repeat(32))];
        let verdict_hashes = vec!["bb".repeat(32)];

        save_merge_projection_pending(
            &owner_repo,
            pr_number,
            head_sha,
            &MergeProjectionPendingSaveRequest {
                merge_sha: head_sha,
                source_branch: "ticket/RFC-0019/TCK-00617",
                merge_receipt_hash: &format!("b3-256:{}", "cc".repeat(32)),
                merged_at_iso: "2026-02-17T00:00:00Z",
                gate_job_id: "job-123",
                gate_receipt_id: "receipt-123",
                policy_hash: &format!("b3-256:{}", "dd".repeat(32)),
                gate_evidence_hashes: &gate_hashes,
                verdict_hashes: &verdict_hashes,
                last_error: "projection timeout",
                attempt_count: 2,
                source: "test",
            },
        )
        .expect("save pending merge projection");

        let loaded = load_merge_projection_pending(&owner_repo, pr_number, head_sha)
            .expect("load pending merge projection")
            .expect("pending merge projection present");
        assert_eq!(loaded.pr_number, pr_number);
        assert_eq!(loaded.head_sha, head_sha);
        assert_eq!(loaded.merge_sha, head_sha);
        assert_eq!(loaded.attempt_count, 2);
        assert_eq!(loaded.last_error, "projection timeout");

        clear_merge_projection_pending(&owner_repo, pr_number, head_sha)
            .expect("clear pending merge projection");
        let reloaded = load_merge_projection_pending(&owner_repo, pr_number, head_sha)
            .expect("reload after clear");
        assert!(reloaded.is_none());
    }

    #[test]
    fn list_merge_projection_pending_for_repo_returns_saved_records() {
        let owner_repo = unique_repo("merge-pending-list");
        let first_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let second_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let gate_hashes = vec![format!("b3-256:{}", "11".repeat(32))];
        let verdict_hashes = vec!["22".repeat(32)];

        save_merge_projection_pending(
            &owner_repo,
            100,
            first_sha,
            &MergeProjectionPendingSaveRequest {
                merge_sha: first_sha,
                source_branch: "ticket/RFC-0019/TCK-00617-a",
                merge_receipt_hash: &format!("b3-256:{}", "33".repeat(32)),
                merged_at_iso: "2026-02-17T00:00:00Z",
                gate_job_id: "job-a",
                gate_receipt_id: "receipt-a",
                policy_hash: &format!("b3-256:{}", "44".repeat(32)),
                gate_evidence_hashes: &gate_hashes,
                verdict_hashes: &verdict_hashes,
                last_error: "network",
                attempt_count: 1,
                source: "test",
            },
        )
        .expect("save first pending record");
        save_merge_projection_pending(
            &owner_repo,
            101,
            second_sha,
            &MergeProjectionPendingSaveRequest {
                merge_sha: second_sha,
                source_branch: "ticket/RFC-0019/TCK-00617-b",
                merge_receipt_hash: &format!("b3-256:{}", "55".repeat(32)),
                merged_at_iso: "2026-02-17T00:01:00Z",
                gate_job_id: "job-b",
                gate_receipt_id: "receipt-b",
                policy_hash: &format!("b3-256:{}", "66".repeat(32)),
                gate_evidence_hashes: &gate_hashes,
                verdict_hashes: &verdict_hashes,
                last_error: "rate limit",
                attempt_count: 3,
                source: "test",
            },
        )
        .expect("save second pending record");

        let listed = list_merge_projection_pending_for_repo(&owner_repo, 8)
            .expect("list pending merge projection");
        assert!(listed.len() >= 2);
        assert!(listed.iter().any(|entry| entry.pr_number == 100));
        assert!(listed.iter().any(|entry| entry.pr_number == 101));
    }

    #[test]
    fn merge_projection_pending_rejects_invalid_hash_material() {
        let owner_repo = unique_repo("merge-pending-invalid");
        let pr_number = 200;
        let head_sha = "cccccccccccccccccccccccccccccccccccccccc";
        let gate_hashes = vec![format!("b3-256:{}", "11".repeat(32))];
        let invalid_verdict_hashes = vec![format!("b3-256:{}", "22".repeat(32))];

        let err = save_merge_projection_pending(
            &owner_repo,
            pr_number,
            head_sha,
            &MergeProjectionPendingSaveRequest {
                merge_sha: head_sha,
                source_branch: "ticket/RFC-0019/TCK-00617-c",
                merge_receipt_hash: &format!("b3-256:{}", "33".repeat(32)),
                merged_at_iso: "2026-02-17T00:02:00Z",
                gate_job_id: "job-c",
                gate_receipt_id: "receipt-c",
                policy_hash: &format!("b3-256:{}", "44".repeat(32)),
                gate_evidence_hashes: &gate_hashes,
                verdict_hashes: &invalid_verdict_hashes,
                last_error: "network",
                attempt_count: 1,
                source: "test",
            },
        )
        .expect_err("invalid verdict hashes must fail");
        assert!(err.contains("64-char hex digests"));
    }

    #[test]
    fn list_merge_projection_pending_for_repo_respects_limit() {
        let owner_repo = unique_repo("merge-pending-limit");
        let first_sha = "dddddddddddddddddddddddddddddddddddddddd";
        let second_sha = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let gate_hashes = vec![format!("b3-256:{}", "11".repeat(32))];
        let verdict_hashes = vec!["22".repeat(32)];

        save_merge_projection_pending(
            &owner_repo,
            300,
            first_sha,
            &MergeProjectionPendingSaveRequest {
                merge_sha: first_sha,
                source_branch: "ticket/limit-a",
                merge_receipt_hash: &format!("b3-256:{}", "33".repeat(32)),
                merged_at_iso: "2026-02-17T00:00:00Z",
                gate_job_id: "job-limit-a",
                gate_receipt_id: "receipt-limit-a",
                policy_hash: &format!("b3-256:{}", "44".repeat(32)),
                gate_evidence_hashes: &gate_hashes,
                verdict_hashes: &verdict_hashes,
                last_error: "first",
                attempt_count: 1,
                source: "test",
            },
        )
        .expect("save first pending record");

        save_merge_projection_pending(
            &owner_repo,
            301,
            second_sha,
            &MergeProjectionPendingSaveRequest {
                merge_sha: second_sha,
                source_branch: "ticket/limit-b",
                merge_receipt_hash: &format!("b3-256:{}", "55".repeat(32)),
                merged_at_iso: "2026-02-17T00:01:00Z",
                gate_job_id: "job-limit-b",
                gate_receipt_id: "receipt-limit-b",
                policy_hash: &format!("b3-256:{}", "66".repeat(32)),
                gate_evidence_hashes: &gate_hashes,
                verdict_hashes: &verdict_hashes,
                last_error: "second",
                attempt_count: 2,
                source: "test",
            },
        )
        .expect("save second pending record");

        let listed = list_merge_projection_pending_for_repo(&owner_repo, 1).expect("list pending");
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn load_pr_identity_by_head_sha_returns_match() {
        let owner_repo = unique_repo("identity-by-head");
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        save_identity(
            &owner_repo,
            640,
            head_sha,
            Some("ticket/TCK-00640"),
            None,
            "test",
        )
        .expect("save identity");
        let loaded = load_pr_identity_by_head_sha(&owner_repo, head_sha)
            .expect("load identity by head")
            .expect("identity should exist");
        assert_eq!(loaded.pr_number, 640);
        assert_eq!(loaded.owner_repo, owner_repo);
        assert_eq!(loaded.head_sha, head_sha);
    }

    #[test]
    fn load_pr_identity_by_head_sha_rejects_ambiguous_matches() {
        let owner_repo = unique_repo("identity-by-head-ambiguous");
        let head_sha = "89abcdef0123456789abcdef0123456789abcdef";
        save_identity(
            &owner_repo,
            640,
            head_sha,
            Some("ticket/TCK-00640-a"),
            None,
            "test",
        )
        .expect("save first identity");
        save_identity(
            &owner_repo,
            641,
            head_sha,
            Some("ticket/TCK-00640-b"),
            None,
            "test",
        )
        .expect("save second identity");

        let err = load_pr_identity_by_head_sha(&owner_repo, head_sha)
            .expect_err("ambiguous head identity must fail closed");
        assert!(err.contains("ambiguous projection identity"));
    }
}
