//! Verdict projection and decision-authority helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_jcs;
use sha2::Digest;
use subtle::ConstantTimeEq;

use super::github_auth::resolve_local_reviewer_identity;
use super::target::resolve_pr_target;
use super::types::{
    TerminationAuthority, allocate_local_comment_id, normalize_decision_dimension, now_iso8601,
    sanitize_for_path, validate_expected_head_sha,
};
use super::{fenced_yaml, findings_store, github_projection, projection_store};
use crate::exit_codes::codes as exit_codes;

const DECISION_MARKER: &str = "apm2-review-verdict:v1";
const DECISION_SCHEMA: &str = "apm2.review.verdict.v1";
const PROJECTION_VERDICT_SCHEMA: &str = "apm2.fac.projection.verdict.v1";
const PROJECTION_REVIEWER_SCHEMA: &str = "apm2.fac.projection.reviewer.v1";

const SECURITY_DIMENSION: &str = "security";
const CODE_QUALITY_DIMENSION: &str = "code-quality";
const ACTIVE_DIMENSIONS: [&str; 2] = [SECURITY_DIMENSION, CODE_QUALITY_DIMENSION];
const VERDICT_PROJECTION_FILE: &str = "verdict_projection.json";
const PROJECTION_INTEGRITY_ROLE: &str = "decision_projection";
const PROJECTION_SECRET_MAX_FILE_BYTES: u64 = 128;
const PROJECTION_SECRET_LEN_BYTES: usize = 32;
const PROJECTION_SECRET_MAX_ENCODED_CHARS: usize = 128;
type HmacSha256 = Hmac<sha2::Sha256>;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backend_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionProjectionRecord {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    updated_at: String,
    decision_comment_id: u64,
    #[serde(default)]
    decision_comment_url: String,
    #[serde(default)]
    decision_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    integrity_hmac: Option<String>,
    #[serde(default)]
    dimensions: BTreeMap<String, DecisionEntry>,
}

#[derive(Serialize)]
struct DecisionProjectionRecordIntegrityBinding<'a> {
    schema: &'a str,
    owner_repo: &'a str,
    pr_number: u32,
    head_sha: &'a str,
    updated_at: &'a str,
    decision_comment_id: u64,
    decision_comment_url: &'a str,
    decision_signature: &'a str,
    dimensions: &'a BTreeMap<String, DecisionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionReviewerIdentity {
    schema: String,
    reviewer_id: String,
    updated_at: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerdictProjectionDimensionSnapshot {
    pub dimension: String,
    pub decision: String,
    pub reviewed_sha: String,
    pub reason: String,
    pub reviewed_by: String,
    pub reviewed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerdictProjectionSnapshot {
    pub schema: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub overall_decision: String,
    pub fail_closed: bool,
    pub dimensions: Vec<VerdictProjectionDimensionSnapshot>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_comment_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_comment_url: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct ProjectionCompletionSignal {
    pub decision: String,
    pub verdict: String,
    pub decision_comment_id: u64,
    pub decision_author: String,
    pub decision_summary: String,
}

#[derive(Debug, Clone)]
pub struct PersistedVerdictProjection {
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub review_state_type: String,
    pub decision: String,
    pub decision_comment_id: u64,
    pub decision_author: String,
    pub decision_signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionMode {
    Full,
    LocalOnly,
}

fn local_only_author_login_with_fallback(
    resolved: Result<String, String>,
    pr_number: u32,
) -> (String, bool) {
    match resolved {
        Ok(login) => (login, true),
        Err(err) => {
            eprintln!(
                "WARNING: failed to resolve trusted reviewer identity for local-only verdict projection on PR #{pr_number}: {err}; using fallback identity"
            );
            ("fac-local-auto-verdict".to_string(), false)
        },
    }
}

pub(super) fn resolve_verdict_for_dimension(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
) -> Result<Option<String>, String> {
    validate_expected_head_sha(head_sha)?;
    let normalized_dimension = normalize_decision_dimension(dimension)?;
    let home = super::types::apm2_home_dir()?;
    let Some(record) = load_decision_projection_for_home(&home, owner_repo, pr_number, head_sha)?
    else {
        return Ok(None);
    };

    let Some(entry) = record.dimensions.get(normalized_dimension) else {
        return Ok(None);
    };

    let Some(decision) = normalize_decision_value(&entry.decision) else {
        return Err(format!(
            "invalid decision `{}` for dimension `{normalized_dimension}` in verdict projection",
            entry.decision
        ));
    };

    let verdict = match decision {
        "approve" => "PASS",
        "deny" => "FAIL",
        _ => unreachable!("normalize_decision_value only returns approve|deny"),
    };
    Ok(Some(verdict.to_string()))
}

pub fn run_verdict_show(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    json_output: bool,
) -> Result<u8, String> {
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let _ = resolve_expected_author_login(&owner_repo, resolved_pr)?;
    let head_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;
    let home = super::types::apm2_home_dir()?;

    let report = match load_decision_projection_for_home(&home, &owner_repo, resolved_pr, &head_sha)
    {
        Ok(Some(record)) => build_show_report_from_record(&head_sha, &record),
        Ok(None) => missing_projection_report(resolved_pr, &head_sha),
        Err(err) => {
            let mut report = missing_projection_report(resolved_pr, &head_sha);
            report.errors.push(err);
            report.fail_closed = true;
            report
        },
    };

    emit_show_report(&report, json_output)?;
    if report.fail_closed {
        Ok(exit_codes::GENERIC_ERROR)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}

pub fn load_verdict_projection_snapshot(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<Option<VerdictProjectionSnapshot>, String> {
    validate_expected_head_sha(head_sha)?;
    let home = super::types::apm2_home_dir()?;
    let Some(record) = load_decision_projection_for_home(&home, owner_repo, pr_number, head_sha)?
    else {
        return Ok(None);
    };

    let mut errors = Vec::new();
    let mut dimensions = Vec::with_capacity(ACTIVE_DIMENSIONS.len());
    for dimension in ACTIVE_DIMENSIONS {
        let entry = record.dimensions.get(dimension);
        let Some(entry) = entry else {
            dimensions.push(VerdictProjectionDimensionSnapshot {
                dimension: (*dimension).to_string(),
                decision: "pending".to_string(),
                reviewed_sha: record.head_sha.clone(),
                reason: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                model_id: None,
                backend_id: None,
            });
            continue;
        };
        let decision = normalize_decision_value(&entry.decision).map_or_else(
            || {
                errors.push(format!(
                    "invalid decision `{}` for dimension `{dimension}`",
                    entry.decision
                ));
                "pending".to_string()
            },
            ToString::to_string,
        );
        dimensions.push(VerdictProjectionDimensionSnapshot {
            dimension: dimension.to_string(),
            decision,
            reviewed_sha: record.head_sha.clone(),
            reason: entry.reason.clone(),
            reviewed_by: entry.set_by.clone(),
            reviewed_at: entry.set_at.clone(),
            model_id: normalize_optional_text(entry.model_id.as_deref()),
            backend_id: normalize_optional_text(entry.backend_id.as_deref()),
        });
    }

    let overall_decision = aggregate_verdict_projection_overall_decision(&dimensions).to_string();
    Ok(Some(VerdictProjectionSnapshot {
        schema: DECISION_SCHEMA.to_string(),
        pr_number: record.pr_number,
        head_sha: record.head_sha,
        overall_decision,
        fail_closed: !errors.is_empty(),
        dimensions,
        errors,
        source_comment_id: if record.decision_comment_id == 0 {
            None
        } else {
            Some(record.decision_comment_id)
        },
        source_comment_url: if record.decision_comment_url.trim().is_empty() {
            None
        } else {
            Some(record.decision_comment_url.clone())
        },
        updated_at: record.updated_at,
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn persist_verdict_projection(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    dimension: &str,
    decision: &str,
    reason: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    json_output: bool,
) -> Result<PersistedVerdictProjection, String> {
    persist_verdict_projection_impl(
        repo,
        pr_number,
        sha,
        dimension,
        decision,
        reason,
        model_id,
        backend_id,
        ProjectionMode::Full,
        true,
        json_output,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn persist_verdict_projection_local_only(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    dimension: &str,
    decision: &str,
    reason: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
) -> Result<PersistedVerdictProjection, String> {
    persist_verdict_projection_impl(
        repo,
        pr_number,
        sha,
        dimension,
        decision,
        reason,
        model_id,
        backend_id,
        ProjectionMode::LocalOnly,
        false,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn persist_verdict_projection_impl(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    dimension: &str,
    decision: &str,
    reason: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    projection_mode: ProjectionMode,
    emit_report: bool,
    json_output: bool,
) -> Result<PersistedVerdictProjection, String> {
    let normalized_dimension = normalize_decision_dimension(dimension)?;
    let normalized_decision = normalize_decision_value(decision)
        .ok_or_else(|| format!("invalid verdict decision `{decision}` (expected approve|deny)"))?;

    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let (expected_author_login, persist_trusted_reviewer_id) = match projection_mode {
        ProjectionMode::Full => (
            resolve_expected_author_login(&owner_repo, resolved_pr)?,
            true,
        ),
        ProjectionMode::LocalOnly => local_only_author_login_with_fallback(
            resolve_expected_author_login(&owner_repo, resolved_pr),
            resolved_pr,
        ),
    };
    let head_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;
    let home = super::types::apm2_home_dir()?;
    let _projection_lock = acquire_projection_lock_for_home(&home, &owner_repo, resolved_pr)?;

    let mut record = load_decision_projection_for_home(&home, &owner_repo, resolved_pr, &head_sha)?
        .unwrap_or_else(|| {
            let seeded_comment_id = {
                let latest_projection =
                    load_latest_projection_for_home(&home, &owner_repo, resolved_pr)
                        .ok()
                        .flatten()
                        .map(|value| value.decision_comment_id)
                        .filter(|value| *value > 0);
                let latest_cached_comment = max_cached_issue_comment_id(&owner_repo, resolved_pr);
                match (latest_projection, latest_cached_comment) {
                    (Some(lhs), Some(rhs)) => Some(lhs.max(rhs)),
                    (Some(value), None) | (None, Some(value)) => Some(value),
                    (None, None) => None,
                }
            };
            DecisionProjectionRecord {
                schema: PROJECTION_VERDICT_SCHEMA.to_string(),
                owner_repo: owner_repo.to_ascii_lowercase(),
                pr_number: resolved_pr,
                head_sha: head_sha.to_ascii_lowercase(),
                updated_at: now_iso8601(),
                decision_comment_id: allocate_local_comment_id(resolved_pr, seeded_comment_id),
                decision_comment_url: String::new(),
                decision_signature: String::new(),
                integrity_hmac: None,
                dimensions: BTreeMap::new(),
            }
        });

    record.schema = PROJECTION_VERDICT_SCHEMA.to_string();
    record.owner_repo = owner_repo.to_ascii_lowercase();
    record.pr_number = resolved_pr;
    record.head_sha = head_sha.to_ascii_lowercase();
    record.updated_at = now_iso8601();

    if let Some(existing) = record.dimensions.get(normalized_dimension)
        && normalize_decision_value(&existing.decision) == Some("deny")
        && normalized_decision == "approve"
    {
        return Err(format!(
            "deny verdict is sticky for PR #{resolved_pr} SHA {} dimension `{normalized_dimension}`",
            record.head_sha
        ));
    }

    record.dimensions.insert(
        normalized_dimension.to_string(),
        DecisionEntry {
            decision: normalized_decision.to_string(),
            reason: reason.unwrap_or_default().trim().to_string(),
            set_by: expected_author_login.clone(),
            set_at: now_iso8601(),
            model_id: normalize_optional_text(model_id),
            backend_id: normalize_optional_text(backend_id),
        },
    );

    let payload = projection_record_to_payload(&record);
    record.decision_signature = signature_for_payload(&payload)?;

    match projection_mode {
        ProjectionMode::Full => {
            let (projected_comment_id, projected_comment_url) =
                project_decision_comment(&owner_repo, resolved_pr, &record, &payload)?;
            record.decision_comment_id = projected_comment_id;
            record.decision_comment_url = projected_comment_url;
        },
        ProjectionMode::LocalOnly => {
            if record.decision_comment_id == 0 {
                record.decision_comment_id = allocate_local_comment_id(
                    resolved_pr,
                    max_cached_issue_comment_id(&owner_repo, resolved_pr),
                );
            }
            if record.decision_comment_url.trim().is_empty() {
                record.decision_comment_url =
                    local_comment_url(&owner_repo, resolved_pr, record.decision_comment_id);
            }
        },
    }

    save_decision_projection_for_home(&home, &record)?;
    let _ = projection_store::save_identity_with_context(
        &owner_repo,
        resolved_pr,
        &head_sha,
        "verdict.set",
    );
    if persist_trusted_reviewer_id {
        let _ = projection_store::save_trusted_reviewer_id(
            &owner_repo,
            resolved_pr,
            &expected_author_login,
        );
    }

    if emit_report {
        let report = build_show_report_from_record(&head_sha, &record);
        emit_show_report(&report, json_output)?;
    }

    Ok(PersistedVerdictProjection {
        owner_repo,
        pr_number: resolved_pr,
        head_sha,
        review_state_type: dimension_to_state_review_type(normalized_dimension).to_string(),
        decision: normalized_decision.to_string(),
        decision_comment_id: record.decision_comment_id,
        decision_author: expected_author_login,
        decision_signature: record.decision_signature,
    })
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

    if let Some(value) = super::state::resolve_local_review_head_sha(pr_number) {
        return Ok(value);
    }

    Err(format!(
        "missing local head SHA for PR #{pr_number}; pass --sha explicitly or run a local FAC flow that persists identity first"
    ))
}

fn resolve_expected_author_login(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    if let Some(cached) = projection_store::load_trusted_reviewer_id(owner_repo, pr_number)? {
        return Ok(cached);
    }

    let login = resolve_local_reviewer_identity();
    let _ = projection_store::save_trusted_reviewer_id(owner_repo, pr_number, &login);
    Ok(login)
}

fn projection_record_to_payload(record: &DecisionProjectionRecord) -> DecisionComment {
    DecisionComment {
        schema: DECISION_SCHEMA.to_string(),
        pr: record.pr_number,
        sha: record.head_sha.clone(),
        updated_at: record.updated_at.clone(),
        dimensions: record.dimensions.clone(),
    }
}

fn project_decision_comment(
    owner_repo: &str,
    pr_number: u32,
    record: &DecisionProjectionRecord,
    payload: &DecisionComment,
) -> Result<(u64, String), String> {
    let body = render_decision_comment_body(owner_repo, pr_number, &record.head_sha, payload)?;

    let mut comment_id = record.decision_comment_id;
    if comment_id == 0 {
        comment_id = allocate_local_comment_id(
            pr_number,
            max_cached_issue_comment_id(owner_repo, pr_number),
        );
    }

    let mut comment_url = if record.decision_comment_url.trim().is_empty() {
        local_comment_url(owner_repo, pr_number, comment_id)
    } else {
        record.decision_comment_url.clone()
    };

    let can_patch_existing = comment_url.starts_with("https://github.com/") && comment_id > 0;
    if can_patch_existing {
        match github_projection::update_issue_comment(owner_repo, comment_id, &body) {
            Ok(()) => return Ok((comment_id, comment_url)),
            Err(err) => {
                eprintln!(
                    "WARNING: failed to project decision comment update to GitHub for PR #{pr_number}: {err}"
                );
            },
        }
    }

    match github_projection::create_issue_comment(owner_repo, pr_number, &body) {
        Ok(response) => Ok((response.id, response.html_url)),
        Err(err) => {
            eprintln!(
                "WARNING: failed to project decision comment create to GitHub for PR #{pr_number}: {err}"
            );
            comment_url = local_comment_url(owner_repo, pr_number, comment_id);
            Ok((comment_id, comment_url))
        },
    }
}

fn local_comment_url(owner_repo: &str, pr_number: u32, comment_id: u64) -> String {
    format!("local://fac_projection/{owner_repo}/pr-{pr_number}/issue_comments#{comment_id}")
}

fn projection_pr_dir_for_home(home: &Path, owner_repo: &str, pr_number: u32) -> PathBuf {
    home.join("fac_projection")
        .join("repos")
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}"))
}

fn projection_sha_dir_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> PathBuf {
    projection_pr_dir_for_home(home, owner_repo, pr_number)
        .join(format!("sha-{}", sanitize_for_path(head_sha)))
}

fn projection_record_path_for_home(home: &Path, owner_repo: &str, pr_number: u32) -> PathBuf {
    projection_pr_dir_for_home(home, owner_repo, pr_number).join(VERDICT_PROJECTION_FILE)
}

fn projection_record_sha_path_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> PathBuf {
    projection_sha_dir_for_home(home, owner_repo, pr_number, head_sha).join(VERDICT_PROJECTION_FILE)
}

fn projection_lock_path_for_home(home: &Path, owner_repo: &str, pr_number: u32) -> PathBuf {
    projection_pr_dir_for_home(home, owner_repo, pr_number).join("verdict_projection.lock")
}

fn projection_secrets_dir(home: &Path) -> PathBuf {
    home.join("fac_projection").join("secrets")
}

fn projection_secret_path(home: &Path, owner_repo: &str, pr_number: u32) -> PathBuf {
    projection_secrets_dir(home)
        .join(PROJECTION_INTEGRITY_ROLE)
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}.secret"))
}

#[cfg(unix)]
fn open_secret_for_read(path: &Path) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            err
        } else {
            std::io::Error::new(
                err.kind(),
                format!("failed to open projection secret {}: {err}", path.display()),
            )
        }
    })
}

#[cfg(not(unix))]
fn open_secret_for_read(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new().read(true).open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            err
        } else {
            std::io::Error::new(
                err.kind(),
                format!("failed to open projection secret {}: {err}", path.display()),
            )
        }
    })
}

fn read_secret_hex_bytes(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let mut file = match open_secret_for_read(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to open projection secret {}: {err}",
                path.display()
            ));
        },
    };
    let size = file
        .metadata()
        .map_err(|err| format!("failed to stat projection secret {}: {err}", path.display()))?
        .len();
    if size > PROJECTION_SECRET_MAX_FILE_BYTES {
        return Err(format!(
            "projection secret {} exceeds maximum size ({} > {})",
            path.display(),
            size,
            PROJECTION_SECRET_MAX_FILE_BYTES
        ));
    }
    let mut encoded = String::new();
    file.read_to_string(&mut encoded)
        .map_err(|err| format!("failed to read projection secret {}: {err}", path.display()))?;
    let encoded = encoded.trim();
    if encoded.is_empty() {
        return Ok(None);
    }
    if encoded.len() > PROJECTION_SECRET_MAX_ENCODED_CHARS {
        return Err(format!(
            "projection secret {} exceeds maximum encoded length",
            path.display()
        ));
    }
    let secret = hex::decode(encoded).map_err(|err| {
        format!(
            "failed to decode projection secret {}: {err}",
            path.display()
        )
    })?;
    if secret.len() != PROJECTION_SECRET_LEN_BYTES {
        return Err(format!(
            "projection secret {} has invalid length {} (expected {})",
            path.display(),
            secret.len(),
            PROJECTION_SECRET_LEN_BYTES
        ));
    }
    Ok(Some(secret))
}

fn write_secret_atomic(path: &Path, encoded_secret: &str) -> Result<(), String> {
    super::types::ensure_parent_dir(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("projection secret path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create projection secret temp file: {err}"))?;
    #[cfg(unix)]
    {
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to set projection secret temp file mode: {err}"))?;
    }
    temp.write_all(encoded_secret.as_bytes()).map_err(|err| {
        format!(
            "failed to write projection secret {}: {err}",
            path.display()
        )
    })?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync projection secret {}: {err}", path.display()))?;
    temp.persist(path).map_err(|err| {
        format!(
            "failed to persist projection secret {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

fn rotate_secret(path: &Path) -> Result<Vec<u8>, String> {
    let mut secret = [0u8; PROJECTION_SECRET_LEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let encoded = hex::encode(secret);
    write_secret_atomic(path, &encoded)?;
    Ok(secret.to_vec())
}

fn read_or_rotate_secret(path: &Path) -> Result<Vec<u8>, String> {
    read_secret_hex_bytes(path)?.map_or_else(|| rotate_secret(path), Ok)
}

fn projection_record_binding_payload(record: &DecisionProjectionRecord) -> Result<Vec<u8>, String> {
    let binding = DecisionProjectionRecordIntegrityBinding {
        schema: &record.schema,
        owner_repo: &record.owner_repo,
        pr_number: record.pr_number,
        head_sha: &record.head_sha,
        updated_at: &record.updated_at,
        decision_comment_id: record.decision_comment_id,
        decision_comment_url: &record.decision_comment_url,
        decision_signature: &record.decision_signature,
        dimensions: &record.dimensions,
    };
    serde_jcs::to_vec(&binding)
        .map_err(|err| format!("failed to build decision projection integrity payload: {err}"))
}

fn compute_hmac(secret: &[u8], payload: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|err| format!("invalid decision projection integrity secret: {err}"))?;
    mac.update(payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_hmac(stored: &str, computed: &str) -> Result<bool, String> {
    let expected = hex::decode(stored)
        .map_err(|err| format!("invalid decision projection integrity_hmac encoding: {err}"))?;
    let actual = hex::decode(computed).map_err(|err| {
        format!("invalid decision projection computed integrity_hmac encoding: {err}")
    })?;
    if expected.len() != actual.len() {
        return Ok(false);
    }
    Ok(expected.ct_eq(actual.as_slice()).into())
}

fn bind_decision_projection_record_integrity(
    home: &Path,
    record: &mut DecisionProjectionRecord,
) -> Result<(), String> {
    let secret = read_or_rotate_secret(&projection_secret_path(
        home,
        &record.owner_repo,
        record.pr_number,
    ))?;
    let payload = projection_record_binding_payload(record)?;
    let computed = compute_hmac(&secret, &payload)?;
    if let Some(stored) = record.integrity_hmac.as_deref() {
        let matches = verify_hmac(stored, &computed)?;
        if !matches {
            return Err("decision projection integrity check failed".to_string());
        }
        return Ok(());
    }
    record.integrity_hmac = Some(computed);
    Ok(())
}

fn verify_decision_projection_record_integrity_without_rotation(
    home: &Path,
    record: &DecisionProjectionRecord,
) -> Result<(), String> {
    let Some(stored) = record.integrity_hmac.as_deref() else {
        return Err(format!(
            "missing decision projection integrity_hmac for {} PR #{} sha {}",
            record.owner_repo, record.pr_number, record.head_sha
        ));
    };
    let secret = read_secret_hex_bytes(&projection_secret_path(
        home,
        &record.owner_repo,
        record.pr_number,
    ))?
    .ok_or_else(|| {
        format!(
            "missing decision projection integrity secret for {} PR #{}",
            record.owner_repo, record.pr_number
        )
    })?;
    let payload = projection_record_binding_payload(record)?;
    let computed = compute_hmac(&secret, &payload)?;
    let matches = verify_hmac(stored, &computed)?;
    if !matches {
        return Err("decision projection integrity check failed".to_string());
    }
    Ok(())
}

fn acquire_projection_lock_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
) -> Result<std::fs::File, String> {
    let lock_path = projection_lock_path_for_home(home, owner_repo, pr_number);
    super::types::ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open verdict projection lock {}: {err}",
                lock_path.display()
            )
        })?;
    lock_file.lock_exclusive().map_err(|err| {
        format!(
            "failed to acquire verdict projection lock {}: {err}",
            lock_path.display()
        )
    })?;
    Ok(lock_file)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    super::types::ensure_parent_dir(path)?;
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

fn load_projection_record_from_path(
    path: &Path,
) -> Result<Option<DecisionProjectionRecord>, String> {
    let bytes = match fs::read(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };

    let record = serde_json::from_slice::<DecisionProjectionRecord>(&bytes)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    Ok(Some(record))
}

fn validate_projection_record_identity(
    record: &DecisionProjectionRecord,
    owner_repo: &str,
    pr_number: u32,
) -> Result<(), String> {
    if record.schema != PROJECTION_VERDICT_SCHEMA {
        return Err(format!(
            "invalid verdict projection schema (expected {PROJECTION_VERDICT_SCHEMA}, got {})",
            record.schema
        ));
    }
    if !record.owner_repo.eq_ignore_ascii_case(owner_repo) {
        return Err(format!(
            "verdict projection repo mismatch: expected {owner_repo}, got {}",
            record.owner_repo
        ));
    }
    if record.pr_number != pr_number {
        return Err(format!(
            "verdict projection PR mismatch: expected #{pr_number}, got #{}",
            record.pr_number
        ));
    }
    Ok(())
}

fn validate_projection_record_sha(
    record: &DecisionProjectionRecord,
    head_sha: &str,
) -> Result<(), String> {
    validate_expected_head_sha(&record.head_sha)?;
    if !record.head_sha.eq_ignore_ascii_case(head_sha) {
        return Err(format!(
            "verdict projection SHA mismatch: expected {head_sha}, got {}",
            record.head_sha
        ));
    }
    Ok(())
}

fn load_latest_projection_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<DecisionProjectionRecord>, String> {
    load_projection_record_from_path(&projection_record_path_for_home(
        home, owner_repo, pr_number,
    ))
}

fn max_cached_issue_comment_id(owner_repo: &str, pr_number: u32) -> Option<u64> {
    projection_store::load_issue_comments_cache::<serde_json::Value>(owner_repo, pr_number)
        .ok()
        .flatten()
        .and_then(|comments| {
            comments
                .into_iter()
                .filter_map(|value| value.get("id").and_then(serde_json::Value::as_u64))
                .max()
        })
}

fn load_decision_projection_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<Option<DecisionProjectionRecord>, String> {
    validate_expected_head_sha(head_sha)?;

    let sha_path = projection_record_sha_path_for_home(home, owner_repo, pr_number, head_sha);
    if let Some(record) = load_projection_record_from_path(&sha_path)? {
        validate_projection_record_identity(&record, owner_repo, pr_number)?;
        validate_projection_record_sha(&record, head_sha)?;
        verify_decision_projection_record_integrity_without_rotation(home, &record)?;
        return Ok(Some(record));
    }

    let Some(record) = load_projection_record_from_path(&projection_record_path_for_home(
        home, owner_repo, pr_number,
    ))?
    else {
        return Ok(None);
    };

    validate_projection_record_identity(&record, owner_repo, pr_number)?;
    validate_expected_head_sha(&record.head_sha)?;
    if !record.head_sha.eq_ignore_ascii_case(head_sha) {
        return Ok(None);
    }
    validate_projection_record_sha(&record, head_sha)?;
    verify_decision_projection_record_integrity_without_rotation(home, &record)?;
    Ok(Some(record))
}

fn save_decision_projection_for_home(
    home: &Path,
    record: &DecisionProjectionRecord,
) -> Result<(), String> {
    validate_expected_head_sha(&record.head_sha)?;
    let mut copy = record.clone();
    copy.integrity_hmac = None;
    bind_decision_projection_record_integrity(home, &mut copy)?;
    let sha_path =
        projection_record_sha_path_for_home(home, &copy.owner_repo, copy.pr_number, &copy.head_sha);
    let root_path = projection_record_path_for_home(home, &copy.owner_repo, copy.pr_number);
    write_json_atomic(&sha_path, &copy)?;
    if let Err(err) = write_json_atomic(&root_path, &copy) {
        let _ = fs::remove_file(&sha_path);
        return Err(err);
    }
    Ok(())
}

fn build_show_report_from_record(
    head_sha: &str,
    record: &DecisionProjectionRecord,
) -> DecisionShowReport {
    let mut errors = Vec::new();
    let mut fail_closed = false;

    for dimension in ACTIVE_DIMENSIONS {
        let Some(entry) = record.dimensions.get(dimension) else {
            // Missing dimensions are normal while verdicts are still pending.
            continue;
        };
        if normalize_decision_value(&entry.decision).is_none() {
            fail_closed = true;
            errors.push(format!(
                "invalid decision `{}` for dimension `{dimension}`",
                entry.decision
            ));
        }
    }

    let mut dimensions = Vec::with_capacity(ACTIVE_DIMENSIONS.len());
    for dimension in ACTIVE_DIMENSIONS {
        let entry = record.dimensions.get(dimension);
        let decision = entry
            .and_then(|value| normalize_decision_value(&value.decision))
            .unwrap_or("unknown")
            .to_string();
        dimensions.push(DimensionDecisionView {
            dimension: dimension.to_string(),
            decision,
            reason: entry.map_or_else(String::new, |value| value.reason.trim().to_string()),
            set_by: entry.map_or_else(String::new, |value| value.set_by.clone()),
            set_at: entry.map_or_else(String::new, |value| value.set_at.clone()),
            sha: record.head_sha.clone(),
            model_id: entry.and_then(|value| normalize_optional_text(value.model_id.as_deref())),
            backend_id: entry
                .and_then(|value| normalize_optional_text(value.backend_id.as_deref())),
        });
    }

    DecisionShowReport {
        schema: DECISION_SCHEMA.to_string(),
        pr_number: record.pr_number,
        head_sha: head_sha.to_string(),
        overall_decision: aggregate_overall_decision(&dimensions).to_string(),
        fail_closed,
        dimensions,
        source_comment_id: Some(record.decision_comment_id),
        source_comment_url: Some(record.decision_comment_url.clone()),
        errors,
    }
}

fn missing_projection_report(pr_number: u32, head_sha: &str) -> DecisionShowReport {
    DecisionShowReport {
        schema: DECISION_SCHEMA.to_string(),
        pr_number,
        head_sha: head_sha.to_string(),
        overall_decision: "pending".to_string(),
        fail_closed: false,
        dimensions: build_unknown_dimension_views(head_sha),
        source_comment_id: None,
        source_comment_url: None,
        errors: Vec::new(),
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
            model_id: None,
            backend_id: None,
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

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
}

fn aggregate_overall_decision(dimensions: &[DimensionDecisionView]) -> &'static str {
    let decisions = dimensions
        .iter()
        .map(|value| value.decision.as_str())
        .collect::<BTreeSet<_>>();
    if decisions.contains("deny") {
        "deny"
    } else if decisions.contains("unknown") {
        "pending"
    } else if decisions.contains("approve") && decisions.len() == 1 {
        "approve"
    } else {
        "pending"
    }
}

fn aggregate_verdict_projection_overall_decision(
    dimensions: &[VerdictProjectionDimensionSnapshot],
) -> &'static str {
    let decisions = dimensions
        .iter()
        .map(|value| value.decision.as_str())
        .collect::<BTreeSet<_>>();

    if decisions.contains("deny") {
        "deny"
    } else if decisions.contains("pending") {
        "pending"
    } else if decisions.contains("approve") && decisions.len() == 1 {
        "approve"
    } else {
        "pending"
    }
}

fn signature_for_payload(payload: &DecisionComment) -> Result<String, String> {
    let canonical = serde_jcs::to_vec(payload)
        .map_err(|err| format!("failed to serialize decision projection payload: {err}"))?;
    let digest = sha2::Sha256::digest(canonical);
    Ok(hex::encode(digest))
}

fn normalize_signature_hex(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("empty decision signature".to_string());
    }
    let normalized = trimmed.to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid decision signature `{trimmed}` (expected 64 lowercase hex chars)"
        ));
    }
    Ok(normalized)
}

fn resolve_verified_decision_signature(
    record: &DecisionProjectionRecord,
) -> Result<String, String> {
    let expected = normalize_signature_hex(
        &signature_for_payload(&projection_record_to_payload(record))
            .map_err(|err| format!("failed to compute expected decision signature: {err}"))?,
    )?;
    if record.decision_signature.trim().is_empty() {
        return Ok(expected);
    }
    let stored = normalize_signature_hex(&record.decision_signature)?;
    if stored != expected {
        return Err(
            "decision projection signature mismatch: stored signature does not match payload digest"
                .to_string(),
        );
    }
    Ok(stored)
}

fn review_type_to_dimension(review_type: &str) -> Result<&'static str, String> {
    match review_type.trim().to_ascii_lowercase().as_str() {
        "security" => Ok(SECURITY_DIMENSION),
        "quality" | "code-quality" => Ok(CODE_QUALITY_DIMENSION),
        other => Err(format!(
            "unsupported review_type `{other}` (expected security|quality)"
        )),
    }
}

fn parse_projection_reviewer_payload(path: &Path, bytes: &[u8]) -> Result<String, String> {
    let payload: ProjectionReviewerIdentity = serde_json::from_slice(bytes).map_err(|err| {
        format!(
            "failed to parse reviewer projection {}: {err}",
            path.display()
        )
    })?;
    if payload.schema != PROJECTION_REVIEWER_SCHEMA {
        return Err(format!(
            "invalid reviewer projection schema in {}: {}",
            path.display(),
            payload.schema
        ));
    }
    let reviewer = payload.reviewer_id.trim();
    if reviewer.is_empty() {
        return Err(format!("empty reviewer identity in {}", path.display()));
    }
    Ok(reviewer.to_string())
}

fn load_projection_reviewer_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
) -> Result<String, String> {
    let path = projection_pr_dir_for_home(home, owner_repo, pr_number).join("reviewer.json");
    let bytes = fs::read(&path).map_err(|err| {
        format!(
            "failed to read reviewer projection {}: {err}",
            path.display()
        )
    })?;
    parse_projection_reviewer_payload(&path, &bytes)
}

fn load_projection_reviewer_optional_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<String>, String> {
    let path = projection_pr_dir_for_home(home, owner_repo, pr_number).join("reviewer.json");
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to read reviewer projection {}: {err}",
                path.display()
            ));
        },
    };
    parse_projection_reviewer_payload(&path, &bytes).map(Some)
}

pub fn resolve_termination_authority_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
    run_id: &str,
) -> Result<TerminationAuthority, String> {
    validate_expected_head_sha(head_sha)?;
    let dimension = review_type_to_dimension(review_type)?;
    let trusted_reviewer = load_projection_reviewer_for_home(home, owner_repo, pr_number)?;
    let record = load_decision_projection_for_home(home, owner_repo, pr_number, head_sha)?
        .ok_or_else(|| {
            format!(
                "missing decision projection for PR #{pr_number} sha {head_sha} (trusted reviewer: {trusted_reviewer})"
            )
        })?;
    let decision_entry = record.dimensions.get(dimension).ok_or_else(|| {
        format!(
            "decision projection for PR #{pr_number} sha {head_sha} is missing `{dimension}` dimension"
        )
    })?;
    if normalize_decision_value(&decision_entry.decision).is_none() {
        return Err(format!(
            "decision projection for PR #{pr_number} sha {head_sha} has unsupported `{dimension}` value: {}",
            decision_entry.decision
        ));
    }
    if !decision_entry
        .set_by
        .eq_ignore_ascii_case(&trusted_reviewer)
    {
        return Err(format!(
            "decision projection author mismatch for PR #{pr_number} sha {head_sha}: expected `{trusted_reviewer}` got `{}`",
            decision_entry.set_by
        ));
    }

    let signature = resolve_verified_decision_signature(&record).map_err(|err| {
        format!(
            "decision projection for PR #{pr_number} sha {head_sha} failed integrity check: {err}"
        )
    })?;

    Ok(TerminationAuthority::new(
        owner_repo,
        pr_number,
        review_type,
        head_sha,
        run_id,
        record.decision_comment_id,
        &trusted_reviewer,
        &now_iso8601(),
        &signature,
    ))
}

pub fn resolve_completion_signal_from_projection_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
) -> Result<Option<ProjectionCompletionSignal>, String> {
    validate_expected_head_sha(head_sha)?;
    let dimension = review_type_to_dimension(review_type)?;
    let Some(trusted_reviewer) =
        load_projection_reviewer_optional_for_home(home, owner_repo, pr_number)?
    else {
        return Ok(None);
    };
    let Some(record) = load_decision_projection_for_home(home, owner_repo, pr_number, head_sha)?
    else {
        return Ok(None);
    };
    let Some(decision_entry) = record.dimensions.get(dimension) else {
        return Ok(None);
    };
    if !decision_entry
        .set_by
        .eq_ignore_ascii_case(&trusted_reviewer)
    {
        return Ok(None);
    }

    let Some(decision) = normalize_decision_value(&decision_entry.decision) else {
        return Err(format!(
            "decision projection for PR #{pr_number} sha {head_sha} has unsupported `{dimension}` value: {}",
            decision_entry.decision
        ));
    };
    let verdict = match decision {
        "approve" => "PASS",
        "deny" => "FAIL",
        _ => unreachable!("normalize_decision_value only returns approve|deny"),
    };

    let signature = resolve_verified_decision_signature(&record).map_err(|err| {
        format!(
            "decision projection for PR #{pr_number} sha {head_sha} failed integrity check: {err}"
        )
    })?;

    Ok(Some(ProjectionCompletionSignal {
        decision: decision.to_string(),
        verdict: verdict.to_string(),
        decision_comment_id: record.decision_comment_id,
        decision_author: trusted_reviewer,
        decision_summary: signature,
    }))
}

#[derive(Debug, Clone, Serialize)]
struct DecisionCommentFinding {
    finding_id: String,
    #[serde(rename = "type")]
    finding_type: String,
    severity: String,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reviewer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_pointer: Option<String>,
    timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
struct DecisionCommentProjectionPayload {
    schema: String,
    pr: u32,
    sha: String,
    updated_at: String,
    dimensions: BTreeMap<String, DecisionEntry>,
    findings: Vec<DecisionCommentFinding>,
}

fn normalize_optional_findings_text(value: Option<&str>) -> Option<String> {
    let raw = value?;
    if raw.trim().is_empty() {
        None
    } else {
        Some(raw.to_string())
    }
}

fn collect_projected_findings(
    bundle: Option<&findings_store::FindingsBundle>,
    payload: &DecisionComment,
) -> Vec<DecisionCommentFinding> {
    let mut projected = Vec::new();
    let mut active_dimensions = payload
        .dimensions
        .keys()
        .map(|value| normalize_decision_dimension(value).unwrap_or(value))
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if let Some(bundle) = bundle {
        for dimension in &bundle.dimensions {
            let normalized = normalize_decision_dimension(&dimension.dimension)
                .map_or_else(|_| dimension.dimension.clone(), ToString::to_string);
            active_dimensions.insert(normalized);
        }
    }

    for dimension in active_dimensions {
        let Some(bundle) = bundle else {
            continue;
        };
        let Some(stored_dimension) = findings_store::find_dimension(bundle, &dimension) else {
            continue;
        };
        for finding in &stored_dimension.findings {
            projected.push(DecisionCommentFinding {
                finding_id: finding.finding_id.clone(),
                finding_type: dimension.clone(),
                severity: finding.severity.clone(),
                summary: finding.summary.clone(),
                risk: normalize_optional_findings_text(finding.risk.as_deref()),
                impact: normalize_optional_findings_text(finding.impact.as_deref()),
                location: normalize_optional_findings_text(finding.location.as_deref()),
                body: normalize_optional_findings_text(finding.details.as_deref()),
                reviewer_id: normalize_optional_findings_text(finding.reviewer_id.as_deref()),
                evidence_digest: normalize_optional_findings_text(Some(&finding.evidence_digest)),
                evidence_pointer: normalize_optional_findings_text(Some(
                    &finding.raw_evidence_pointer,
                )),
                timestamp: finding.created_at.clone(),
            });
        }
    }
    projected
}

fn render_decision_comment_body(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    payload: &DecisionComment,
) -> Result<String, String> {
    let findings_bundle = match findings_store::load_findings_bundle(
        owner_repo, pr_number, head_sha,
    ) {
        Ok(value) => value,
        Err(err) => {
            eprintln!(
                "WARNING: failed to load findings for verdict projection on PR #{pr_number}: {err}"
            );
            None
        },
    };
    let projection_payload = DecisionCommentProjectionPayload {
        schema: payload.schema.clone(),
        pr: payload.pr,
        sha: payload.sha.clone(),
        updated_at: payload.updated_at.clone(),
        dimensions: payload.dimensions.clone(),
        findings: collect_projected_findings(findings_bundle.as_ref(), payload),
    };
    fenced_yaml::render_marked_yaml_comment(DECISION_MARKER, &projection_payload)
}

fn emit_show_report(report: &DecisionShowReport, json_output: bool) -> Result<(), String> {
    let _ = json_output;
    println!(
        "{}",
        serde_json::to_string_pretty(report)
            .map_err(|err| format!("failed to serialize decision report: {err}"))?
    );
    Ok(())
}

fn dimension_to_state_review_type(dimension: &str) -> &str {
    match dimension {
        "code-quality" => "quality",
        other => other,
    }
}

#[cfg(test)]
pub(super) fn seed_decision_projection_for_home_for_tests(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
    reviewer_login: &str,
    comment_id: u64,
) -> Result<(), String> {
    validate_expected_head_sha(head_sha)?;
    let normalized_head_sha = head_sha.to_ascii_lowercase();
    let now = now_iso8601();
    let mut dimensions = BTreeMap::new();
    dimensions.insert(
        review_type_to_dimension(review_type)?.to_string(),
        DecisionEntry {
            decision: "approve".to_string(),
            reason: "test decision authority".to_string(),
            set_by: reviewer_login.to_string(),
            set_at: now.clone(),
            model_id: None,
            backend_id: None,
        },
    );
    let payload = DecisionComment {
        schema: DECISION_SCHEMA.to_string(),
        pr: pr_number,
        sha: normalized_head_sha.clone(),
        updated_at: now.clone(),
        dimensions: dimensions.clone(),
    };
    let record = DecisionProjectionRecord {
        schema: PROJECTION_VERDICT_SCHEMA.to_string(),
        owner_repo: owner_repo.to_ascii_lowercase(),
        pr_number,
        head_sha: normalized_head_sha,
        updated_at: now.clone(),
        decision_comment_id: comment_id,
        decision_comment_url: local_comment_url(owner_repo, pr_number, comment_id),
        decision_signature: signature_for_payload(&payload)?,
        integrity_hmac: None,
        dimensions,
    };
    save_decision_projection_for_home(home, &record)?;

    let reviewer = ProjectionReviewerIdentity {
        schema: PROJECTION_REVIEWER_SCHEMA.to_string(),
        reviewer_id: reviewer_login.to_string(),
        updated_at: now,
    };
    let reviewer_path =
        projection_pr_dir_for_home(home, owner_repo, pr_number).join("reviewer.json");
    write_json_atomic(&reviewer_path, &reviewer)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::{
        DECISION_SCHEMA, DecisionComment, DecisionEntry, DecisionProjectionRecord,
        build_show_report_from_record, missing_projection_report, render_decision_comment_body,
        resolve_completion_signal_from_projection_for_home,
    };

    #[test]
    fn resolve_completion_signal_reads_projection_record() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let owner_repo = "example/repo";
        let pr_number = 441;
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let pr_dir = super::projection_pr_dir_for_home(home, owner_repo, pr_number);
        fs::create_dir_all(&pr_dir).expect("create projection dir");

        let reviewer_projection = serde_json::json!({
            "schema": "apm2.fac.projection.reviewer.v1",
            "reviewer_id": "fac-bot",
            "updated_at": "2026-02-13T00:00:00Z"
        });
        fs::write(
            pr_dir.join("reviewer.json"),
            serde_json::to_vec_pretty(&reviewer_projection).expect("serialize reviewer"),
        )
        .expect("write reviewer projection");

        let mut dimensions = BTreeMap::new();
        dimensions.insert(
            "security".to_string(),
            DecisionEntry {
                decision: "approve".to_string(),
                reason: String::new(),
                set_by: "fac-bot".to_string(),
                set_at: "2026-02-13T00:00:00Z".to_string(),
                model_id: None,
                backend_id: None,
            },
        );

        let payload = DecisionComment {
            schema: DECISION_SCHEMA.to_string(),
            pr: pr_number,
            sha: head_sha.to_string(),
            updated_at: "2026-02-13T00:00:00Z".to_string(),
            dimensions: dimensions.clone(),
        };
        let record = DecisionProjectionRecord {
            schema: "apm2.fac.projection.verdict.v1".to_string(),
            owner_repo: owner_repo.to_string(),
            pr_number,
            head_sha: head_sha.to_string(),
            updated_at: "2026-02-13T00:00:00Z".to_string(),
            decision_comment_id: 88,
            decision_comment_url: "local://fac_projection/example/repo/pr-441/issue_comments#88"
                .to_string(),
            decision_signature: super::signature_for_payload(&payload)
                .expect("serialize decision payload"),
            dimensions,
            integrity_hmac: None,
        };

        super::save_decision_projection_for_home(home, &record).expect("write decision projection");

        let resolved = resolve_completion_signal_from_projection_for_home(
            home, owner_repo, pr_number, "security", head_sha,
        )
        .expect("resolve completion signal")
        .expect("signal should resolve");
        assert_eq!(resolved.decision, "approve");
        assert_eq!(resolved.verdict, "PASS");
        assert_eq!(resolved.decision_comment_id, 88);
        assert_eq!(resolved.decision_author, "fac-bot");
        assert_eq!(resolved.decision_summary.len(), 64);
    }

    #[test]
    fn missing_projection_report_is_pending_without_fail_closed() {
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let report = missing_projection_report(441, head_sha);
        assert_eq!(report.pr_number, 441);
        assert_eq!(report.head_sha, head_sha);
        assert_eq!(report.overall_decision, "pending");
        assert!(!report.fail_closed);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn decision_comment_body_is_yaml_only_with_structured_findings_array() {
        let mut dimensions = BTreeMap::new();
        dimensions.insert(
            "security".to_string(),
            DecisionEntry {
                decision: "approve".to_string(),
                reason: "all checks passed".to_string(),
                set_by: "fac-bot".to_string(),
                set_at: "2026-02-14T00:00:00Z".to_string(),
                model_id: None,
                backend_id: None,
            },
        );
        let payload = DecisionComment {
            schema: DECISION_SCHEMA.to_string(),
            pr: 615,
            sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            updated_at: "2026-02-14T00:00:00Z".to_string(),
            dimensions,
        };

        let body = render_decision_comment_body(
            "example/repo",
            615,
            "0123456789abcdef0123456789abcdef01234567",
            &payload,
        )
        .expect("render decision comment");

        assert!(body.contains("<!-- apm2-review-verdict:v1 -->"));
        assert!(body.contains("```yaml"));
        assert!(body.contains("findings:"));
        assert!(!body.contains("## FAC Findings"));
        assert!(!body.contains("### security"));
    }

    #[test]
    fn partial_projection_report_stays_pending_without_fail_closed() {
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let mut dimensions = BTreeMap::new();
        dimensions.insert(
            "security".to_string(),
            DecisionEntry {
                decision: "approve".to_string(),
                reason: String::new(),
                set_by: "fac-bot".to_string(),
                set_at: "2026-02-13T00:00:00Z".to_string(),
                model_id: None,
                backend_id: None,
            },
        );
        let record = DecisionProjectionRecord {
            schema: "apm2.fac.projection.verdict.v1".to_string(),
            owner_repo: "example/repo".to_string(),
            pr_number: 441,
            head_sha: head_sha.to_string(),
            updated_at: "2026-02-13T00:00:00Z".to_string(),
            decision_comment_id: 88,
            decision_comment_url: "local://fac_projection/example/repo/pr-441/issue_comments#88"
                .to_string(),
            decision_signature: String::new(),
            dimensions,
            integrity_hmac: None,
        };
        let report = build_show_report_from_record(head_sha, &record);
        assert_eq!(report.overall_decision, "pending");
        assert!(!report.fail_closed);
    }

    #[test]
    fn invalid_decision_value_remains_fail_closed() {
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let mut dimensions = BTreeMap::new();
        dimensions.insert(
            "security".to_string(),
            DecisionEntry {
                decision: "invalid".to_string(),
                reason: String::new(),
                set_by: "fac-bot".to_string(),
                set_at: "2026-02-13T00:00:00Z".to_string(),
                model_id: None,
                backend_id: None,
            },
        );
        dimensions.insert(
            "code-quality".to_string(),
            DecisionEntry {
                decision: "approve".to_string(),
                reason: String::new(),
                set_by: "fac-bot".to_string(),
                set_at: "2026-02-13T00:00:00Z".to_string(),
                model_id: None,
                backend_id: None,
            },
        );
        let record = DecisionProjectionRecord {
            schema: "apm2.fac.projection.verdict.v1".to_string(),
            owner_repo: "example/repo".to_string(),
            pr_number: 441,
            head_sha: head_sha.to_string(),
            updated_at: "2026-02-13T00:00:00Z".to_string(),
            decision_comment_id: 88,
            decision_comment_url: "local://fac_projection/example/repo/pr-441/issue_comments#88"
                .to_string(),
            decision_signature: String::new(),
            dimensions,
            integrity_hmac: None,
        };
        let report = build_show_report_from_record(head_sha, &record);
        assert!(report.fail_closed);
        assert!(!report.errors.is_empty());
    }

    #[test]
    fn local_only_author_login_uses_resolved_identity() {
        let (login, persist_identity) =
            super::local_only_author_login_with_fallback(Ok("fac-bot".to_string()), 441);
        assert_eq!(login, "fac-bot");
        assert!(persist_identity);
    }

    #[test]
    fn local_only_author_login_fallback_disables_reviewer_identity_persist() {
        let (login, persist_identity) = super::local_only_author_login_with_fallback(
            Err("failed to read reviewer identity".to_string()),
            441,
        );
        assert_eq!(login, "fac-local-auto-verdict");
        assert!(!persist_identity);
    }
}
