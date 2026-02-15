//! `ReviewStateFile` persistence, pulse files, file locking, and process
//! checks.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use fs2::FileExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::types::{
    PulseFile, ReviewRunState, ReviewRunStatus, ReviewStateEntry, ReviewStateFile,
    TERMINAL_INTEGRITY_FAILURE, TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED, apm2_home_dir,
    ensure_parent_dir, entry_pr_number, is_verdict_finalized_agent_stop_reason, sanitize_for_path,
    split_owner_repo, validate_expected_head_sha,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRunTerminationReceipt {
    pub schema: String,
    pub emitted_at: String,
    pub repo: String,
    pub pr_number: u32,
    pub review_type: String,
    pub run_id: String,
    pub head_sha: String,
    pub decision_comment_id: u64,
    pub decision_author: String,
    pub decision_summary: String,
    pub integrity_hmac: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRunCompletionReceipt {
    pub schema: String,
    pub emitted_at: String,
    pub repo: String,
    pub pr_number: u32,
    pub review_type: String,
    pub run_id: String,
    pub head_sha: String,
    pub decision: String,
    pub decision_comment_id: u64,
    pub decision_author: String,
    pub decision_summary: String,
    pub integrity_hmac: String,
}

type HmacSha256 = Hmac<Sha256>;
const RUN_SECRET_MAX_FILE_BYTES: u64 = 1024;
const RUN_SECRET_LEN_BYTES: usize = 32;
const RUN_SECRET_MAX_ENCODED_CHARS: usize = 128;
pub const TERMINATION_RECEIPT_SCHEMA: &str = "apm2.review.termination_receipt.v1";
pub const COMPLETION_RECEIPT_SCHEMA: &str = "apm2.review.completion_receipt.v1";

// ── Path helpers ────────────────────────────────────────────────────────────

fn review_state_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_state.json"))
}

fn review_state_lock_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_state.lock"))
}

fn review_runs_dir_for_home(home: &Path) -> PathBuf {
    home.join("reviews")
}

fn review_run_dir_for_home(home: &Path, pr_number: u32, review_type: &str) -> PathBuf {
    review_runs_dir_for_home(home)
        .join(pr_number.to_string())
        .join(review_type)
}

pub fn review_run_state_path_for_home(home: &Path, pr_number: u32, review_type: &str) -> PathBuf {
    review_run_dir_for_home(home, pr_number, review_type).join("state.json")
}

fn review_run_secret_path_for_home(home: &Path, pr_number: u32, review_type: &str) -> PathBuf {
    review_run_dir_for_home(home, pr_number, review_type).join("run_secret")
}

fn review_run_termination_receipt_path_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> PathBuf {
    review_run_dir_for_home(home, pr_number, review_type).join("termination_receipt.json")
}

fn review_run_completion_receipt_path_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> PathBuf {
    review_run_dir_for_home(home, pr_number, review_type).join("completion_receipt.json")
}

fn bind_review_run_state_integrity_for_home(
    home: &Path,
    state: &mut ReviewRunState,
) -> Result<(), String> {
    let secret = match read_run_secret_for_home(home, state.pr_number, &state.review_type)? {
        Some(secret) => secret,
        None => rotate_run_secret_for_home(home, state.pr_number, &state.review_type)?,
    };

    if state.integrity_hmac.is_none() {
        bind_review_run_state_integrity(state, &secret)?;
        return Ok(());
    }

    match verify_review_run_state_integrity(state, &secret) {
        Ok(true) => Ok(()),
        Ok(false) => Err("run-state integrity check failed".to_string()),
        Err(err) => Err(format!("run-state integrity check error: {err}")),
    }
}

#[derive(Serialize)]
struct ReviewRunStateIntegrityBinding<'a> {
    run_id: &'a str,
    owner_repo: &'a str,
    pr_number: u32,
    head_sha: &'a str,
    review_type: &'a str,
    status: &'a str,
    sequence_number: u32,
    restart_count: u32,
    started_at: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal_reason: Option<&'a str>,
    pid: Option<u32>,
    proc_start_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_run_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_head_sha: Option<&'a str>,
}

#[derive(Serialize)]
struct ReviewRunCompletionReceiptIntegrityBinding<'a> {
    schema: &'a str,
    emitted_at: &'a str,
    repo: &'a str,
    pr_number: u32,
    review_type: &'a str,
    run_id: &'a str,
    head_sha: &'a str,
    decision: &'a str,
    decision_comment_id: u64,
    decision_author: &'a str,
    decision_summary: &'a str,
}

#[derive(Serialize)]
struct ReviewRunTerminationReceiptIntegrityBinding<'a> {
    schema: &'a str,
    emitted_at: &'a str,
    repo: &'a str,
    pr_number: u32,
    review_type: &'a str,
    run_id: &'a str,
    head_sha: &'a str,
    decision_comment_id: u64,
    decision_author: &'a str,
    decision_summary: &'a str,
    outcome: &'a str,
    outcome_reason: Option<&'a str>,
}

fn open_secret_for_read(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            "run secret missing".to_string()
        } else {
            format!("failed to open run secret {}: {err}", path.display())
        }
    })
}

fn sync_parent_dir(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    let dir = File::open(parent)
        .map_err(|err| format!("failed to open parent dir {}: {err}", parent.display()))?;
    dir.sync_all()
        .map_err(|err| format!("failed to sync parent dir {}: {err}", parent.display()))
}

fn write_secret_atomic(path: &Path, encoded_secret: &str) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("run secret path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create run secret temp file: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let permissions = std::fs::Permissions::from_mode(0o600);
        temp.as_file()
            .set_permissions(permissions)
            .map_err(|err| format!("failed to set run secret temp file mode: {err}"))?;
    }
    temp.write_all(encoded_secret.as_bytes())
        .map_err(|err| format!("failed to write run secret temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync run secret temp file: {err}"))?;
    temp.persist(path)
        .map_err(|err| format!("failed to persist run secret {}: {err}", path.display()))?;
    sync_parent_dir(path)
}

pub fn rotate_run_secret_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<Vec<u8>, String> {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let path = review_run_secret_path_for_home(home, pr_number, review_type);
    let encoded = hex::encode(secret);
    write_secret_atomic(&path, &encoded)?;
    Ok(secret.to_vec())
}

pub fn read_run_secret_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<Vec<u8>>, String> {
    let path = review_run_secret_path_for_home(home, pr_number, review_type);
    let mut file = match open_secret_for_read(&path) {
        Ok(file) => file,
        Err(err) if err == "run secret missing" => return Ok(None),
        Err(err) => return Err(err),
    };
    let size = file
        .metadata()
        .map_err(|err| format!("failed to stat run secret {}: {err}", path.display()))?
        .len();
    if size > RUN_SECRET_MAX_FILE_BYTES {
        return Err(format!(
            "run secret {} exceeds maximum size ({} > {})",
            path.display(),
            size,
            RUN_SECRET_MAX_FILE_BYTES
        ));
    }
    let mut encoded = String::new();
    file.read_to_string(&mut encoded)
        .map_err(|err| format!("failed to read run secret {}: {err}", path.display()))?;
    let encoded = encoded.trim();
    if encoded.is_empty() {
        return Ok(None);
    }
    if encoded.len() > RUN_SECRET_MAX_ENCODED_CHARS {
        return Err(format!(
            "run secret {} exceeds maximum encoded length",
            path.display()
        ));
    }
    let secret = hex::decode(encoded)
        .map_err(|err| format!("failed to decode run secret {}: {err}", path.display()))?;
    if secret.len() != RUN_SECRET_LEN_BYTES {
        return Err(format!(
            "run secret {} has invalid length {} (expected {})",
            path.display(),
            secret.len(),
            RUN_SECRET_LEN_BYTES
        ));
    }
    Ok(Some(secret))
}

#[allow(dead_code)]
pub fn review_run_secret_path(pr_number: u32, review_type: &str) -> Result<PathBuf, String> {
    Ok(review_run_secret_path_for_home(
        &apm2_home_dir()?,
        pr_number,
        review_type,
    ))
}

pub fn run_state_integrity_binding_payload(state: &ReviewRunState) -> Result<Vec<u8>, String> {
    let binding = ReviewRunStateIntegrityBinding {
        run_id: &state.run_id,
        owner_repo: &state.owner_repo,
        pr_number: state.pr_number,
        head_sha: &state.head_sha,
        review_type: &state.review_type,
        status: state.status.as_str(),
        sequence_number: state.sequence_number,
        restart_count: state.restart_count,
        started_at: &state.started_at,
        terminal_reason: state.terminal_reason.as_deref(),
        pid: state.pid,
        proc_start_time: state.proc_start_time,
        previous_run_id: state.previous_run_id.as_deref(),
        previous_head_sha: state.previous_head_sha.as_deref(),
    };
    serde_json::to_vec(&binding).map_err(|err| format!("failed to build integrity payload: {err}"))
}

pub fn compute_review_run_state_integrity_hmac(
    state: &ReviewRunState,
    secret: &[u8],
) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|err| format!("invalid integrity secret: {err}"))?;
    let payload = run_state_integrity_binding_payload(state)?;
    mac.update(&payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub fn bind_review_run_state_integrity(
    state: &mut ReviewRunState,
    secret: &[u8],
) -> Result<(), String> {
    state.integrity_hmac = Some(compute_review_run_state_integrity_hmac(state, secret)?);
    Ok(())
}

pub fn verify_review_run_state_integrity(
    state: &ReviewRunState,
    secret: &[u8],
) -> Result<bool, String> {
    let stored = state
        .integrity_hmac
        .as_deref()
        .ok_or_else(|| "state missing integrity_hmac".to_string())?;
    let expected =
        hex::decode(stored).map_err(|err| format!("invalid integrity_hmac encoding: {err}"))?;
    let actual = hex::decode(compute_review_run_state_integrity_hmac(state, secret)?)
        .map_err(|err| format!("invalid computed integrity encoding: {err}"))?;
    if expected.len() != actual.len() {
        return Ok(false);
    }
    Ok(expected.ct_eq(actual.as_slice()).into())
}

fn compute_hmac_hex(payload: &[u8], secret: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|err| format!("invalid integrity secret: {err}"))?;
    mac.update(payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_hmac_hex(stored_hex: &str, computed_hex: &str) -> Result<bool, String> {
    let expected =
        hex::decode(stored_hex).map_err(|err| format!("invalid integrity_hmac encoding: {err}"))?;
    let actual = hex::decode(computed_hex)
        .map_err(|err| format!("invalid computed integrity_hmac encoding: {err}"))?;
    if expected.len() != actual.len() {
        return Ok(false);
    }
    Ok(expected.ct_eq(actual.as_slice()).into())
}

fn completion_receipt_integrity_payload(
    receipt: &ReviewRunCompletionReceipt,
) -> Result<Vec<u8>, String> {
    let binding = ReviewRunCompletionReceiptIntegrityBinding {
        schema: &receipt.schema,
        emitted_at: &receipt.emitted_at,
        repo: &receipt.repo,
        pr_number: receipt.pr_number,
        review_type: &receipt.review_type,
        run_id: &receipt.run_id,
        head_sha: &receipt.head_sha,
        decision: &receipt.decision,
        decision_comment_id: receipt.decision_comment_id,
        decision_author: &receipt.decision_author,
        decision_summary: &receipt.decision_summary,
    };
    serde_json::to_vec(&binding)
        .map_err(|err| format!("failed to build completion receipt integrity payload: {err}"))
}

fn termination_receipt_integrity_payload(
    receipt: &ReviewRunTerminationReceipt,
) -> Result<Vec<u8>, String> {
    let binding = ReviewRunTerminationReceiptIntegrityBinding {
        schema: &receipt.schema,
        emitted_at: &receipt.emitted_at,
        repo: &receipt.repo,
        pr_number: receipt.pr_number,
        review_type: &receipt.review_type,
        run_id: &receipt.run_id,
        head_sha: &receipt.head_sha,
        decision_comment_id: receipt.decision_comment_id,
        decision_author: &receipt.decision_author,
        decision_summary: &receipt.decision_summary,
        outcome: &receipt.outcome,
        outcome_reason: receipt.outcome_reason.as_deref(),
    };
    serde_json::to_vec(&binding)
        .map_err(|err| format!("failed to build termination receipt integrity payload: {err}"))
}

fn bind_completion_receipt_integrity_for_home(
    home: &Path,
    receipt: &mut ReviewRunCompletionReceipt,
) -> Result<(), String> {
    let secret = match read_run_secret_for_home(home, receipt.pr_number, &receipt.review_type)? {
        Some(secret) => secret,
        None => rotate_run_secret_for_home(home, receipt.pr_number, &receipt.review_type)?,
    };
    let payload = completion_receipt_integrity_payload(receipt)?;
    receipt.integrity_hmac = compute_hmac_hex(&payload, &secret)?;
    Ok(())
}

fn verify_completion_receipt_integrity_for_home(
    home: &Path,
    receipt: &ReviewRunCompletionReceipt,
) -> Result<(), String> {
    let Some(secret) = read_run_secret_for_home(home, receipt.pr_number, &receipt.review_type)?
    else {
        return Err(TERMINAL_INTEGRITY_FAILURE.to_string());
    };
    if receipt.integrity_hmac.trim().is_empty() {
        return Err(TERMINAL_INTEGRITY_FAILURE.to_string());
    }
    let payload = completion_receipt_integrity_payload(receipt)?;
    let computed = compute_hmac_hex(&payload, &secret)?;
    let matches = verify_hmac_hex(&receipt.integrity_hmac, &computed)
        .map_err(|_| TERMINAL_INTEGRITY_FAILURE.to_string())?;
    if !matches {
        return Err(TERMINAL_INTEGRITY_FAILURE.to_string());
    }
    Ok(())
}

fn bind_termination_receipt_integrity_for_home(
    home: &Path,
    receipt: &mut ReviewRunTerminationReceipt,
) -> Result<(), String> {
    let secret = match read_run_secret_for_home(home, receipt.pr_number, &receipt.review_type)? {
        Some(secret) => secret,
        None => rotate_run_secret_for_home(home, receipt.pr_number, &receipt.review_type)?,
    };
    let payload = termination_receipt_integrity_payload(receipt)?;
    receipt.integrity_hmac = compute_hmac_hex(&payload, &secret)?;
    Ok(())
}

fn verify_termination_receipt_integrity_for_home(
    home: &Path,
    receipt: &ReviewRunTerminationReceipt,
) -> Result<(), String> {
    let Some(secret) = read_run_secret_for_home(home, receipt.pr_number, &receipt.review_type)?
    else {
        return Err(TERMINAL_INTEGRITY_FAILURE.to_string());
    };
    if receipt.integrity_hmac.trim().is_empty() {
        return Err(TERMINAL_INTEGRITY_FAILURE.to_string());
    }
    let payload = termination_receipt_integrity_payload(receipt)?;
    let computed = compute_hmac_hex(&payload, &secret)?;
    let matches = verify_hmac_hex(&receipt.integrity_hmac, &computed)
        .map_err(|_| TERMINAL_INTEGRITY_FAILURE.to_string())?;
    if !matches {
        return Err(TERMINAL_INTEGRITY_FAILURE.to_string());
    }
    Ok(())
}

fn review_runs_dir_path() -> Result<PathBuf, String> {
    Ok(review_runs_dir_for_home(&apm2_home_dir()?))
}

pub fn review_run_state_path(pr_number: u32, review_type: &str) -> Result<PathBuf, String> {
    Ok(review_run_state_path_for_home(
        &apm2_home_dir()?,
        pr_number,
        review_type,
    ))
}

pub fn review_locks_dir_path_for_home(home: &Path) -> PathBuf {
    home.join("review_locks")
}

#[allow(dead_code)]
pub fn review_locks_dir_path() -> Result<PathBuf, String> {
    Ok(review_locks_dir_path_for_home(&apm2_home_dir()?))
}

#[allow(clippy::unnecessary_wraps)]
pub fn review_lock_path_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
) -> Result<PathBuf, String> {
    let safe_repo = sanitize_for_path(owner_repo);
    let safe_type = sanitize_for_path(review_type);
    Ok(review_locks_dir_path_for_home(home)
        .join(format!("{safe_repo}-pr{pr_number}-{safe_type}.lock")))
}

pub fn review_lock_path(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
) -> Result<PathBuf, String> {
    review_lock_path_for_home(&apm2_home_dir()?, owner_repo, pr_number, review_type)
}

fn review_pulses_dir_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_pulses"))
}

fn pulse_file_path(pr_number: u32, review_type: &str) -> Result<PathBuf, String> {
    let suffix = match review_type {
        "security" => "review_pulse_security.json",
        "quality" => "review_pulse_quality.json",
        other => {
            return Err(format!(
                "invalid pulse review type: {other} (expected security|quality)"
            ));
        },
    };
    Ok(review_pulses_dir_path()?.join(format!("pr{pr_number}_{suffix}")))
}

fn legacy_pulse_file_path(review_type: &str) -> Result<PathBuf, String> {
    let suffix = match review_type {
        "security" => "review_pulse_security.json",
        "quality" => "review_pulse_quality.json",
        other => {
            return Err(format!(
                "invalid pulse review type: {other} (expected security|quality)"
            ));
        },
    };
    Ok(apm2_home_dir()?.join(suffix))
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ReviewRunStateLoad {
    Present(ReviewRunState),
    Missing {
        path: PathBuf,
    },
    Corrupt {
        path: PathBuf,
        error: String,
    },
    Ambiguous {
        dir: PathBuf,
        candidates: Vec<PathBuf>,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct LegacyReviewRunStateV1 {
    run_id: String,
    pr_url: String,
    pr_number: u32,
    head_sha: String,
    review_type: String,
    reviewer_role: String,
    started_at: String,
    status: ReviewRunStatus,
    #[serde(default)]
    terminal_reason: Option<String>,
    #[serde(default)]
    model_id: Option<String>,
    #[serde(default)]
    backend_id: Option<String>,
    #[serde(default)]
    restart_count: u32,
    sequence_number: u32,
    #[serde(default)]
    previous_run_id: Option<String>,
    #[serde(default)]
    previous_head_sha: Option<String>,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    proc_start_time: Option<u64>,
    #[serde(default)]
    integrity_hmac: Option<String>,
}

fn owner_repo_from_pr_url(pr_url: &str) -> Option<String> {
    let normalized = pr_url
        .trim()
        .split(['#', '?'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches('/');
    let path = normalized
        .strip_prefix("https://github.com/")
        .or_else(|| normalized.strip_prefix("http://github.com/"))?;
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    let route = parts.next()?;
    let pr_number = parts.next()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    if !route.eq_ignore_ascii_case("pull") || pr_number.is_empty() {
        return None;
    }
    let owner_repo = format!("{owner}/{repo}");
    split_owner_repo(&owner_repo).ok()?;
    Some(owner_repo.to_ascii_lowercase())
}

fn normalize_verdict_finalized_state_for_home(
    home: &Path,
    state_path: &Path,
    state: &mut ReviewRunState,
) -> Result<(), String> {
    let Some(reason) = state.terminal_reason.as_deref() else {
        return Ok(());
    };
    if state.status != ReviewRunStatus::Failed || !is_verdict_finalized_agent_stop_reason(reason) {
        return Ok(());
    }

    state.status = ReviewRunStatus::Done;
    state.terminal_reason = Some(TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED.to_string());
    // Re-bind integrity because the terminal status and reason changed.
    state.integrity_hmac = None;
    let persisted = persist_and_reload_run_state_for_home(home, state).map_err(|err| {
        format!(
            "failed to normalize verdict-finalized terminal state {}: {err}",
            state_path.display()
        )
    })?;
    *state = persisted;
    Ok(())
}

fn migrate_legacy_run_state_for_home(
    home: &Path,
    state_path: &Path,
    expected_pr_number: u32,
    expected_review_type: &str,
    content: &[u8],
) -> Result<Option<ReviewRunState>, String> {
    let Ok(legacy) = serde_json::from_slice::<LegacyReviewRunStateV1>(content) else {
        return Ok(None);
    };

    if legacy.pr_number != expected_pr_number {
        return Err(format!(
            "legacy state PR mismatch (expected {}, got {})",
            expected_pr_number, legacy.pr_number
        ));
    }
    if !legacy
        .review_type
        .eq_ignore_ascii_case(expected_review_type)
    {
        return Err(format!(
            "legacy state review type mismatch (expected {}, got {})",
            expected_review_type, legacy.review_type
        ));
    }

    let owner_repo = owner_repo_from_pr_url(&legacy.pr_url).ok_or_else(|| {
        format!(
            "legacy state contains invalid pr_url `{}` (cannot derive owner/repo)",
            legacy.pr_url
        )
    })?;
    let mut migrated = ReviewRunState {
        run_id: legacy.run_id,
        owner_repo,
        pr_number: legacy.pr_number,
        head_sha: legacy.head_sha,
        review_type: legacy.review_type,
        reviewer_role: legacy.reviewer_role,
        started_at: legacy.started_at,
        status: legacy.status,
        terminal_reason: legacy.terminal_reason,
        model_id: legacy.model_id,
        backend_id: legacy.backend_id,
        restart_count: legacy.restart_count,
        sequence_number: legacy.sequence_number,
        previous_run_id: legacy.previous_run_id,
        previous_head_sha: legacy.previous_head_sha,
        pid: legacy.pid,
        proc_start_time: legacy.proc_start_time,
        integrity_hmac: legacy.integrity_hmac,
    };

    if migrated.status == ReviewRunStatus::Failed
        && migrated
            .terminal_reason
            .as_deref()
            .is_some_and(is_verdict_finalized_agent_stop_reason)
    {
        migrated.status = ReviewRunStatus::Done;
        migrated.terminal_reason = Some(TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED.to_string());
    }
    // Legacy integrity payload included `pr_url`; re-bind against canonical
    // `owner_repo`.
    migrated.integrity_hmac = None;
    let persisted = persist_and_reload_run_state_for_home(home, &migrated).map_err(|err| {
        format!(
            "failed to persist migrated legacy state {}: {err}",
            state_path.display()
        )
    })?;
    Ok(Some(persisted))
}

fn persist_and_reload_run_state_for_home(
    home: &Path,
    state: &ReviewRunState,
) -> Result<ReviewRunState, String> {
    let path = write_review_run_state_for_home(home, state)?;
    let bytes = fs::read(&path).map_err(|err| {
        format!(
            "failed to read persisted run-state {}: {err}",
            path.display()
        )
    })?;
    serde_json::from_slice::<ReviewRunState>(&bytes).map_err(|err| {
        format!(
            "failed to parse persisted run-state {}: {err}",
            path.display()
        )
    })
}

fn review_run_state_candidates(dir: &Path) -> Result<Vec<PathBuf>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut candidates = fs::read_dir(dir)
        .map_err(|err| format!("failed to read run-state dir {}: {err}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("state")
                        && std::path::Path::new(name)
                            .extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
                })
        })
        .collect::<Vec<_>>();
    candidates.sort();
    Ok(candidates)
}

fn load_review_run_state_unverified_for_home_inner(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunStateLoad, String> {
    let dir = review_run_dir_for_home(home, pr_number, review_type);
    let canonical = review_run_state_path_for_home(home, pr_number, review_type);
    let candidates = review_run_state_candidates(&dir)?;
    if candidates.is_empty() {
        return Ok(ReviewRunStateLoad::Missing { path: canonical });
    }
    if candidates.len() > 1 {
        return Ok(ReviewRunStateLoad::Ambiguous { dir, candidates });
    }
    let candidate = candidates
        .into_iter()
        .next()
        .ok_or_else(|| "run-state candidate resolution failed".to_string())?;
    if candidate != canonical {
        return Ok(ReviewRunStateLoad::Ambiguous {
            dir,
            candidates: vec![candidate],
        });
    }
    let content = match fs::read(&candidate) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ReviewRunStateLoad::Missing { path: canonical });
        },
        Err(err) => {
            return Ok(ReviewRunStateLoad::Corrupt {
                path: candidate,
                error: format!("failed to read run-state file: {err}"),
            });
        },
    };
    let mut parsed = match serde_json::from_slice::<ReviewRunState>(&content) {
        Ok(state) => state,
        Err(parse_err) => match migrate_legacy_run_state_for_home(
            home,
            &candidate,
            pr_number,
            review_type,
            &content,
        ) {
            Ok(Some(migrated)) => migrated,
            Ok(None) => {
                return Ok(ReviewRunStateLoad::Corrupt {
                    path: candidate,
                    error: format!("failed to parse run-state JSON: {parse_err}"),
                });
            },
            Err(migration_err) => {
                return Ok(ReviewRunStateLoad::Corrupt {
                    path: candidate,
                    error: format!(
                        "failed to parse run-state JSON: {parse_err}; legacy migration failed: {migration_err}"
                    ),
                });
            },
        },
    };
    if parsed.pr_number != pr_number || !parsed.review_type.eq_ignore_ascii_case(review_type) {
        return Ok(ReviewRunStateLoad::Corrupt {
            path: candidate,
            error: format!(
                "run-state identity mismatch (expected pr={pr_number} type={review_type}, got pr={} type={})",
                parsed.pr_number, parsed.review_type
            ),
        });
    }
    if let Err(err) = normalize_verdict_finalized_state_for_home(home, &candidate, &mut parsed) {
        return Ok(ReviewRunStateLoad::Corrupt {
            path: candidate,
            error: err,
        });
    }
    Ok(ReviewRunStateLoad::Present(parsed))
}

pub fn load_review_run_state_unverified_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunStateLoad, String> {
    load_review_run_state_unverified_for_home_inner(home, pr_number, review_type)
}

pub fn load_review_run_state_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunStateLoad, String> {
    load_review_run_state_verified_for_home(home, pr_number, review_type)
}

pub fn load_review_run_state_verified_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunStateLoad, String> {
    let canonical = review_run_state_path_for_home(home, pr_number, review_type);
    let run_state_load =
        load_review_run_state_unverified_for_home_inner(home, pr_number, review_type)?;
    match run_state_load {
        ReviewRunStateLoad::Present(state) => {
            if let Err(err) = verify_review_run_state_integrity_binding(home, &state) {
                return Ok(ReviewRunStateLoad::Corrupt {
                    path: canonical,
                    error: format!("run-state integrity verification failed: {err}"),
                });
            }
            Ok(ReviewRunStateLoad::Present(state))
        },
        other => Ok(other),
    }
}

#[allow(dead_code)]
pub fn load_review_run_state_verified(
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunStateLoad, String> {
    let home = apm2_home_dir()?;
    load_review_run_state_verified_for_home(&home, pr_number, review_type)
}

pub fn load_review_run_state(
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunStateLoad, String> {
    let home = apm2_home_dir()?;
    load_review_run_state_for_home(&home, pr_number, review_type)
}

#[allow(dead_code)]
pub fn load_review_run_state_unverified(
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunStateLoad, String> {
    let home = apm2_home_dir()?;
    load_review_run_state_unverified_for_home(&home, pr_number, review_type)
}

pub fn load_review_run_state_strict_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunState>, String> {
    match load_review_run_state_for_home(home, pr_number, review_type)? {
        ReviewRunStateLoad::Present(state) => Ok(Some(state)),
        ReviewRunStateLoad::Missing { .. } => Ok(None),
        ReviewRunStateLoad::Corrupt { path, error } => Err(format!(
            "corrupt-state path={} detail={error}",
            path.display()
        )),
        ReviewRunStateLoad::Ambiguous { dir, candidates } => {
            let rendered = candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            Err(format!(
                "ambiguous-state dir={} candidates={rendered}",
                dir.display()
            ))
        },
    }
}

pub fn load_review_run_state_verified_strict_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunState>, String> {
    match load_review_run_state_verified_for_home(home, pr_number, review_type)? {
        ReviewRunStateLoad::Present(state) => Ok(Some(state)),
        ReviewRunStateLoad::Missing { .. } => Ok(None),
        ReviewRunStateLoad::Corrupt { path, error } => Err(format!(
            "corrupt-state path={} detail={error}",
            path.display()
        )),
        ReviewRunStateLoad::Ambiguous { dir, candidates } => {
            let rendered = candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            Err(format!(
                "ambiguous-state dir={} candidates={rendered}",
                dir.display()
            ))
        },
    }
}

#[allow(dead_code)]
pub fn load_review_run_state_verified_strict(
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunState>, String> {
    let home = apm2_home_dir()?;
    load_review_run_state_verified_strict_for_home(&home, pr_number, review_type)
}

pub fn load_review_run_state_strict(
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunState>, String> {
    let home = apm2_home_dir()?;
    load_review_run_state_strict_for_home(&home, pr_number, review_type)
}

pub fn write_review_run_state(state: &ReviewRunState) -> Result<PathBuf, String> {
    let path = review_run_state_path(state.pr_number, &state.review_type)?;
    let home = apm2_home_dir()?;
    let mut state = state.clone();
    state.integrity_hmac = None; // force re-bind on every write
    bind_review_run_state_integrity_for_home(&home, &mut state)?;
    write_review_run_state_to_path(&path, &state)?;
    if state.status.is_terminal() {
        let _ = remove_pulse_file(state.pr_number, &state.review_type);
    }
    Ok(path)
}

pub fn write_review_run_state_for_home(
    home: &Path,
    state: &ReviewRunState,
) -> Result<PathBuf, String> {
    let path = review_run_state_path_for_home(home, state.pr_number, &state.review_type);
    let mut state = state.clone();
    state.integrity_hmac = None; // force re-bind on every write
    bind_review_run_state_integrity_for_home(home, &mut state)?;
    write_review_run_state_to_path(&path, &state)?;
    if state.status.is_terminal() {
        let _ = remove_pulse_file(state.pr_number, &state.review_type);
    }
    Ok(path)
}

pub fn write_review_run_termination_receipt_for_home(
    home: &Path,
    receipt: &ReviewRunTerminationReceipt,
) -> Result<PathBuf, String> {
    let mut receipt = receipt.clone();
    receipt.schema = TERMINATION_RECEIPT_SCHEMA.to_string();
    bind_termination_receipt_integrity_for_home(home, &mut receipt)?;
    let path =
        review_run_termination_receipt_path_for_home(home, receipt.pr_number, &receipt.review_type);
    ensure_parent_dir(&path)?;
    let payload = serde_json::to_vec_pretty(&receipt)
        .map_err(|err| format!("failed to serialize termination receipt: {err}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("termination receipt path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create termination receipt temp file: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to set termination receipt temp file mode: {err}"))?;
    }
    temp.write_all(&payload)
        .map_err(|err| format!("failed to write termination receipt temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync termination receipt temp file: {err}"))?;
    temp.persist(path.clone())
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(path)
}

pub fn write_review_run_completion_receipt_for_home(
    home: &Path,
    receipt: &ReviewRunCompletionReceipt,
) -> Result<PathBuf, String> {
    let mut receipt = receipt.clone();
    receipt.schema = COMPLETION_RECEIPT_SCHEMA.to_string();
    bind_completion_receipt_integrity_for_home(home, &mut receipt)?;
    let path =
        review_run_completion_receipt_path_for_home(home, receipt.pr_number, &receipt.review_type);
    ensure_parent_dir(&path)?;
    let payload = serde_json::to_vec_pretty(&receipt)
        .map_err(|err| format!("failed to serialize completion receipt: {err}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("completion receipt path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create completion receipt temp file: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to set completion receipt temp file mode: {err}"))?;
    }
    temp.write_all(&payload)
        .map_err(|err| format!("failed to write completion receipt temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync completion receipt temp file: {err}"))?;
    temp.persist(path.clone())
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(path)
}

pub fn load_review_run_completion_receipt_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunCompletionReceipt>, String> {
    let path = review_run_completion_receipt_path_for_home(home, pr_number, review_type);
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to read completion receipt {}: {err}",
                path.display()
            ));
        },
    };
    let receipt: ReviewRunCompletionReceipt = serde_json::from_slice(&bytes).map_err(|err| {
        format!(
            "failed to parse completion receipt {}: {err}",
            path.display()
        )
    })?;
    if receipt.pr_number != pr_number || !receipt.review_type.eq_ignore_ascii_case(review_type) {
        return Err(format!(
            "completion receipt identity mismatch at {}: expected pr={pr_number} type={review_type}, got pr={} type={}",
            path.display(),
            receipt.pr_number,
            receipt.review_type
        ));
    }
    if receipt.schema != COMPLETION_RECEIPT_SCHEMA {
        return Err(format!(
            "completion receipt schema mismatch at {}: expected {}, got {}",
            path.display(),
            COMPLETION_RECEIPT_SCHEMA,
            receipt.schema
        ));
    }
    validate_expected_head_sha(&receipt.head_sha).map_err(|err| {
        format!(
            "completion receipt head sha validation failed at {}: {err}",
            path.display()
        )
    })?;
    verify_completion_receipt_integrity_for_home(home, &receipt).map_err(|err| {
        format!(
            "completion receipt integrity verification failed at {}: {err}",
            path.display()
        )
    })?;
    Ok(Some(receipt))
}

pub fn load_review_run_completion_receipt(
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunCompletionReceipt>, String> {
    let home = apm2_home_dir()?;
    load_review_run_completion_receipt_for_home(&home, pr_number, review_type)
}

pub fn load_review_run_termination_receipt_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunTerminationReceipt>, String> {
    let path = review_run_termination_receipt_path_for_home(home, pr_number, review_type);
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to read termination receipt {}: {err}",
                path.display()
            ));
        },
    };
    let receipt: ReviewRunTerminationReceipt = serde_json::from_slice(&bytes).map_err(|err| {
        format!(
            "failed to parse termination receipt {}: {err}",
            path.display()
        )
    })?;
    if receipt.pr_number != pr_number || !receipt.review_type.eq_ignore_ascii_case(review_type) {
        return Err(format!(
            "termination receipt identity mismatch at {}: expected pr={pr_number} type={review_type}, got pr={} type={}",
            path.display(),
            receipt.pr_number,
            receipt.review_type
        ));
    }
    if receipt.schema != TERMINATION_RECEIPT_SCHEMA {
        return Err(format!(
            "termination receipt schema mismatch at {}: expected {}, got {}",
            path.display(),
            TERMINATION_RECEIPT_SCHEMA,
            receipt.schema
        ));
    }
    validate_expected_head_sha(&receipt.head_sha).map_err(|err| {
        format!(
            "termination receipt head sha validation failed at {}: {err}",
            path.display()
        )
    })?;
    verify_termination_receipt_integrity_for_home(home, &receipt).map_err(|err| {
        format!(
            "termination receipt integrity verification failed at {}: {err}",
            path.display()
        )
    })?;
    Ok(Some(receipt))
}

#[allow(dead_code)]
pub fn load_review_run_termination_receipt(
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunTerminationReceipt>, String> {
    let home = apm2_home_dir()?;
    load_review_run_termination_receipt_for_home(&home, pr_number, review_type)
}

pub fn verify_review_run_state_integrity_binding(
    home: &Path,
    state: &ReviewRunState,
) -> Result<(), String> {
    let secret = match read_run_secret_for_home(home, state.pr_number, &state.review_type)? {
        Some(secret) => secret,
        None => rotate_run_secret_for_home(home, state.pr_number, &state.review_type)?,
    };

    let Some(stored) = state.integrity_hmac.as_deref() else {
        return Err(TERMINAL_INTEGRITY_FAILURE.to_string());
    };
    let expected =
        hex::decode(stored).map_err(|err| format!("failed to decode integrity_hmac: {err}"))?;
    let computed = hex::decode(compute_review_run_state_integrity_hmac(state, &secret)?)
        .map_err(|err| format!("failed to compute integrity_hmac: {err}"))?;
    if expected.len() != computed.len()
        || subtle::ConstantTimeEq::ct_eq(&expected[..], &computed[..]).unwrap_u8() != 1
    {
        return Err(TERMINAL_INTEGRITY_FAILURE.to_string());
    }
    Ok(())
}

pub fn write_review_run_state_to_path(path: &Path, state: &ReviewRunState) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let payload = serde_json::to_vec_pretty(state)
        .map_err(|err| format!("failed to serialize run-state: {err}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("run-state path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create run-state temp file: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to set run-state temp file mode: {err}"))?;
    }
    temp.write_all(&payload)
        .map_err(|err| format!("failed to write run-state temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync run-state temp file: {err}"))?;
    temp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

pub fn next_review_sequence_number_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<u32, String> {
    match load_review_run_state_for_home(home, pr_number, review_type)? {
        ReviewRunStateLoad::Present(state) => Ok(state.sequence_number.saturating_add(1).max(1)),
        ReviewRunStateLoad::Missing { .. } => Ok(1),
        ReviewRunStateLoad::Corrupt { path, error } => Err(format!(
            "corrupt-state path={} detail={error}",
            path.display()
        )),
        ReviewRunStateLoad::Ambiguous { dir, candidates } => {
            let rendered = candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            Err(format!(
                "ambiguous-state dir={} candidates={rendered}",
                dir.display()
            ))
        },
    }
}

pub fn next_review_sequence_number(pr_number: u32, review_type: &str) -> Result<u32, String> {
    let home = apm2_home_dir()?;
    next_review_sequence_number_for_home(&home, pr_number, review_type)
}

pub fn build_review_run_id(
    pr_number: u32,
    review_type: &str,
    sequence_number: u32,
    head_sha: &str,
) -> String {
    let head = &head_sha[..head_sha.len().min(8)];
    format!("pr{pr_number}-{review_type}-s{sequence_number}-{head}")
}

/// Hard cap on directory entries scanned when listing PR numbers.
/// Prevents unbounded CPU time if the review-runs directory contains
/// an adversarial number of entries (denial-of-service mitigation).
/// We scan up to this many raw filesystem entries; within those entries
/// only valid numeric PR directory names are collected.
const MAX_REVIEW_DIR_ENTRIES: usize = 10_000;

/// Maximum number of PR numbers retained after scanning. When more valid
/// PR directories exist than this limit, only the highest (newest) PR
/// numbers are kept — ensuring deterministic, recency-biased retention
/// regardless of filesystem iteration order.
const MAX_REVIEW_PR_NUMBERS: usize = 5_000;

pub fn list_review_pr_numbers() -> Result<Vec<u32>, String> {
    let root = review_runs_dir_path()?;
    list_review_pr_numbers_from_dir(&root, MAX_REVIEW_DIR_ENTRIES, MAX_REVIEW_PR_NUMBERS)
}

/// Deterministic PR number listing with bounded scanning and retention.
///
/// Scans up to `scan_cap` directory entries, collecting valid numeric PR
/// directory names. After scanning, the collected PR numbers are sorted
/// in ascending order and deduplicated. If more than `retain_cap` unique
/// PR numbers exist, only the **highest** (newest) are retained — this
/// guarantees deterministic results regardless of filesystem iteration
/// order. A warning is emitted to stderr when either cap is reached.
fn list_review_pr_numbers_from_dir(
    root: &Path,
    scan_cap: usize,
    retain_cap: usize,
) -> Result<Vec<u32>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(root)
        .map_err(|err| format!("failed to read reviews root {}: {err}", root.display()))?;
    let mut numbers = Vec::new();
    let mut scanned: usize = 0;
    let mut scan_truncated = false;
    for entry in entries {
        scanned += 1;
        if scanned > scan_cap {
            scan_truncated = true;
            break;
        }
        let Ok(entry) = entry else { continue };
        if let Some(pr) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            numbers.push(pr);
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    // Retain only the highest (newest) PR numbers when over the retention cap.
    // Because `numbers` is sorted ascending, we drop the lowest prefix.
    let retain_truncated = numbers.len() > retain_cap;
    if retain_truncated {
        let start = numbers.len() - retain_cap;
        numbers.drain(..start);
    }
    if scan_truncated || retain_truncated {
        eprintln!(
            "warning: review-runs directory listing truncated \
             (scanned={scanned}, scan_cap={scan_cap}, \
             retained={}, retain_cap={retain_cap})",
            numbers.len(),
        );
    }
    Ok(numbers)
}

// ── ReviewStateFile persistence ─────────────────────────────────────────────

impl ReviewStateFile {
    fn load_from_path(path: &Path) -> Result<Self, String> {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
        };
        serde_json::from_str(&content)
            .map_err(|err| format!("failed to parse {}: {err}", path.display()))
    }

    fn save_to_path(&self, path: &Path) -> Result<(), String> {
        ensure_parent_dir(path)?;
        let serialized = serde_json::to_vec_pretty(self)
            .map_err(|err| format!("failed to serialize review state: {err}"))?;

        let parent = path
            .parent()
            .ok_or_else(|| format!("state path has no parent: {}", path.display()))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|err| format!("failed to create temp state file: {err}"))?;
        temp.write_all(&serialized)
            .map_err(|err| format!("failed to write temp state file: {err}"))?;
        temp.as_file()
            .sync_all()
            .map_err(|err| format!("failed to sync temp state file: {err}"))?;
        temp.persist(path)
            .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
        Ok(())
    }
}

// ── State locking ───────────────────────────────────────────────────────────

pub fn with_review_state_shared<T>(
    operation: impl FnOnce(&ReviewStateFile) -> Result<T, String>,
) -> Result<T, String> {
    let lock_path = review_state_lock_path()?;
    let state_path = review_state_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open state lock {}: {err}", lock_path.display()))?;
    FileExt::lock_shared(&lock_file)
        .map_err(|err| format!("failed to lock state {}: {err}", lock_path.display()))?;
    let state = ReviewStateFile::load_from_path(&state_path)?;
    let result = operation(&state);
    drop(lock_file);
    result
}

fn with_review_state_exclusive<T>(
    operation: impl FnOnce(&mut ReviewStateFile) -> Result<T, String>,
) -> Result<T, String> {
    let lock_path = review_state_lock_path()?;
    let state_path = review_state_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open state lock {}: {err}", lock_path.display()))?;
    FileExt::lock_exclusive(&lock_file)
        .map_err(|err| format!("failed to lock state {}: {err}", lock_path.display()))?;
    let mut state = ReviewStateFile::load_from_path(&state_path)?;
    let result = operation(&mut state)?;
    state.save_to_path(&state_path)?;
    drop(lock_file);
    Ok(result)
}

// ── State entry operations ──────────────────────────────────────────────────

pub fn upsert_review_state_entry(run_key: &str, entry: ReviewStateEntry) -> Result<(), String> {
    with_review_state_exclusive(|state| {
        state.reviewers.insert(run_key.to_string(), entry);
        Ok(())
    })
}

pub fn remove_review_state_entry(run_key: &str) -> Result<(), String> {
    with_review_state_exclusive(|state| {
        state.reviewers.remove(run_key);
        Ok(())
    })
}

pub fn find_active_review_entry(
    pr_number: u32,
    review_type: &str,
    head_sha: Option<&str>,
) -> Result<Option<ReviewStateEntry>, String> {
    with_review_state_shared(|state| {
        let mut candidates = state
            .reviewers
            .values()
            .filter(|entry| entry_pr_number(entry).is_some_and(|number| number == pr_number))
            .filter(|entry| entry.review_type.eq_ignore_ascii_case(review_type))
            .filter(|entry| is_process_alive(entry.pid))
            .cloned()
            .collect::<Vec<_>>();
        if let Some(head) = head_sha {
            candidates.retain(|entry| entry.head_sha.eq_ignore_ascii_case(head));
        }
        candidates.sort_by_key(|entry| entry.started_at);
        Ok(candidates.pop())
    })
}

pub fn try_acquire_review_lease(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<File>, String> {
    let lock_path = review_lock_path(owner_repo, pr_number, review_type)?;
    try_acquire_review_lease_at_path(&lock_path)
}

pub fn try_acquire_review_lease_for_home(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<File>, String> {
    let lock_path = review_lock_path_for_home(home, owner_repo, pr_number, review_type)?;
    try_acquire_review_lease_at_path(&lock_path)
}

fn try_acquire_review_lease_at_path(lock_path: &Path) -> Result<Option<File>, String> {
    ensure_parent_dir(lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|err| format!("failed to open review lock {}: {err}", lock_path.display()))?;
    match FileExt::try_lock_exclusive(&lock_file) {
        Ok(()) => Ok(Some(lock_file)),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(err) => Err(format!(
            "failed to acquire review lock {}: {err}",
            lock_path.display()
        )),
    }
}

// ── Run key ─────────────────────────────────────────────────────────────────

pub fn build_run_key(pr_number: u32, review_type: &str, head_sha: &str) -> String {
    let head = &head_sha[..head_sha.len().min(8)];
    let ts = super::types::now_iso8601_millis().replace([':', '.'], "");
    format!("pr{pr_number}-{review_type}-{head}-{ts}")
}

// ── Process aliveness ───────────────────────────────────────────────────────

pub fn is_process_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn parse_process_start_time(stat_content: &str) -> Option<u64> {
    // /proc/<pid>/stat field layout keeps comm in parentheses (field 2),
    // so split from the last ') ' to avoid whitespace/paren ambiguity.
    let (_, tail) = stat_content.rsplit_once(") ")?;
    // tail starts at field 3 ("state"), so field 22 (starttime) is index 19.
    tail.split_whitespace().nth(19)?.parse::<u64>().ok()
}

pub fn get_process_start_time(pid: u32) -> Option<u64> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat_content = fs::read_to_string(stat_path).ok()?;
    parse_process_start_time(&stat_content)
}

// ── Pulse files ─────────────────────────────────────────────────────────────

pub fn write_pulse_file(
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
    run_id: Option<&str>,
) -> Result<(), String> {
    let path = pulse_file_path(pr_number, review_type)?;
    write_pulse_file_to_path(&path, head_sha, run_id)
}

pub fn write_pulse_file_to_path(
    path: &Path,
    head_sha: &str,
    run_id: Option<&str>,
) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let pulse = PulseFile {
        head_sha: head_sha.to_string(),
        run_id: run_id.map(ToString::to_string),
        written_at: Utc::now(),
    };
    let content = serde_json::to_vec_pretty(&pulse)
        .map_err(|err| format!("failed to serialize pulse file: {err}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("pulse path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create pulse temp file: {err}"))?;
    temp.write_all(&content)
        .map_err(|err| format!("failed to write pulse temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync pulse temp file: {err}"))?;
    temp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

pub fn read_pulse_file(pr_number: u32, review_type: &str) -> Result<Option<PulseFile>, String> {
    let path = pulse_file_path(pr_number, review_type)?;
    if let Some(pulse) = read_pulse_file_from_path(&path)? {
        Ok(Some(pulse))
    } else {
        let legacy = legacy_pulse_file_path(review_type)?;
        read_pulse_file_from_path(&legacy)
    }
}

pub fn read_pulse_file_from_path(path: &Path) -> Result<Option<PulseFile>, String> {
    let content = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let pulse = serde_json::from_slice::<PulseFile>(&content)
        .map_err(|err| format!("failed to parse pulse file {}: {err}", path.display()))?;
    Ok(Some(pulse))
}

pub fn resolve_local_review_head_sha(pr_number: u32) -> Option<String> {
    for review_type in ["security", "quality"] {
        let Ok(state) = load_review_run_state(pr_number, review_type) else {
            continue;
        };
        if let ReviewRunStateLoad::Present(entry) = state {
            if entry.status.is_terminal() {
                continue;
            }
            if validate_expected_head_sha(&entry.head_sha).is_ok() {
                return Some(entry.head_sha.to_ascii_lowercase());
            }
        }
    }

    None
}

pub fn remove_pulse_file(pr_number: u32, review_type: &str) -> Result<(), String> {
    let path = pulse_file_path(pr_number, review_type)?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "failed to remove pulse file {}: {err}",
            path.display()
        )),
    }
}

pub fn read_last_lines(path: &Path, max_lines: usize) -> Result<Vec<String>, String> {
    let file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read line: {err}"))?;
        lines.push(line);
        if lines.len() > max_lines {
            let _ = lines.remove(0);
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        ReviewRunStateLoad, bind_review_run_state_integrity, build_review_run_id,
        get_process_start_time, list_review_pr_numbers_from_dir, load_review_run_state_for_home,
        load_review_run_state_strict_for_home, load_review_run_state_verified_for_home,
        next_review_sequence_number_for_home, owner_repo_from_pr_url, parse_process_start_time,
        read_run_secret_for_home, review_lock_path_for_home, review_run_secret_path_for_home,
        review_run_state_path_for_home, rotate_run_secret_for_home,
        try_acquire_review_lease_for_home, verify_review_run_state_integrity,
        write_review_run_state_for_home, write_review_run_state_to_path,
    };
    use crate::commands::fac_review::types::{
        ReviewRunState, ReviewRunStatus, TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED,
        TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED_LEGACY,
    };

    fn sample_state() -> ReviewRunState {
        ReviewRunState {
            run_id: build_review_run_id(
                441,
                "security",
                3,
                "0123456789abcdef0123456789abcdef01234567",
            ),
            owner_repo: "example/repo".to_string(),
            pr_number: 441,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            review_type: "security".to_string(),
            reviewer_role: "fac_reviewer".to_string(),
            started_at: "2026-02-10T00:00:00Z".to_string(),
            status: ReviewRunStatus::Alive,
            terminal_reason: None,
            model_id: Some("gpt-5.3-codex".to_string()),
            backend_id: Some("codex".to_string()),
            restart_count: 1,
            sequence_number: 3,
            previous_run_id: None,
            previous_head_sha: None,
            pid: Some(12345),
            proc_start_time: Some(987_654_321),
            integrity_hmac: None,
        }
    }

    fn dead_pid_for_test() -> u32 {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id();
        let _ = child.wait();
        pid
    }

    #[test]
    fn test_review_run_state_integrity_tamper_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let mut state = sample_state();
        let _ = rotate_run_secret_for_home(home, 441, "security").expect("generate secret");
        let secret = read_run_secret_for_home(home, 441, "security")
            .expect("read secret")
            .expect("secret present");
        bind_review_run_state_integrity(&mut state, &secret).expect("bind integrity");
        assert!(
            verify_review_run_state_integrity(&state, &secret).expect("verify integrity"),
            "tamper check should pass for original state"
        );

        state.proc_start_time = Some(111_111_111);
        assert!(
            !verify_review_run_state_integrity(&state, &secret).expect("verify modified state"),
            "tampered state must fail integrity check"
        );
    }

    #[test]
    fn test_missing_run_secret_is_none() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        assert_eq!(
            read_run_secret_for_home(home, 441, "security").expect("read missing secret"),
            None,
            "missing secret must be None"
        );
        assert_eq!(
            review_run_secret_path_for_home(home, 441, "security")
                .file_name()
                .and_then(|name| name.to_str()),
            Some("run_secret")
        );
    }

    #[test]
    fn test_read_run_secret_rejects_oversized_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let path = review_run_secret_path_for_home(home, 441, "security");
        std::fs::create_dir_all(path.parent().expect("run secret parent")).expect("create dir");
        std::fs::write(&path, "a".repeat(1025)).expect("write oversized run secret");

        let err = read_run_secret_for_home(home, 441, "security")
            .expect_err("oversized run secret must fail closed");
        assert!(
            err.contains("exceeds maximum size") || err.contains("maximum encoded length"),
            "unexpected error detail: {err}"
        );
    }

    #[test]
    fn test_read_run_secret_rejects_non_32_byte_secret() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let path = review_run_secret_path_for_home(home, 441, "security");
        std::fs::create_dir_all(path.parent().expect("run secret parent")).expect("create dir");
        std::fs::write(&path, hex::encode([0u8; 16])).expect("write short run secret");

        let err = read_run_secret_for_home(home, 441, "security")
            .expect_err("non-32-byte run secret must fail closed");
        assert!(
            err.contains("invalid length"),
            "unexpected error detail: {err}"
        );
    }

    #[test]
    fn test_parse_process_start_time_extracts_field_22() {
        let stat =
            "12345 (apm2 worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 21 22";
        assert_eq!(parse_process_start_time(stat), Some(424_242));
    }

    #[test]
    fn test_owner_repo_from_pr_url_parses_github_pull_url() {
        assert_eq!(
            owner_repo_from_pr_url("https://github.com/Test-Org/Test-Repo/pull/42"),
            Some("test-org/test-repo".to_string())
        );
        assert_eq!(
            owner_repo_from_pr_url("https://github.com/test-org/test-repo/pull/42#issuecomment-1"),
            Some("test-org/test-repo".to_string())
        );
        assert_eq!(owner_repo_from_pr_url("not-a-pr-url"), None);
    }

    #[test]
    fn test_get_process_start_time_current_pid() {
        let current_pid = std::process::id();
        assert!(
            get_process_start_time(current_pid).is_some(),
            "expected /proc start time for current process"
        );
    }

    #[test]
    fn test_review_run_state_roundtrip() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state = sample_state();
        write_review_run_state_for_home(home, &state).expect("write run-state");
        let loaded = load_review_run_state_for_home(home, 441, "security").expect("load run-state");
        match loaded {
            ReviewRunStateLoad::Present(found) => {
                assert_eq!(found.run_id, state.run_id);
                assert_eq!(found.sequence_number, 3);
                assert_eq!(found.status, ReviewRunStatus::Alive);
            },
            other => panic!("expected present state, got {other:?}"),
        }
    }

    #[test]
    fn test_load_review_run_state_migrates_legacy_pr_url_schema_and_rebinds_integrity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let path = review_run_state_path_for_home(home, 441, "security");
        std::fs::create_dir_all(path.parent().expect("path parent")).expect("create dir");

        let legacy = serde_json::json!({
            "run_id": "pr441-security-s3-01234567",
            "pr_url": "https://github.com/example/repo/pull/441",
            "pr_number": 441,
            "head_sha": "0123456789abcdef0123456789abcdef01234567",
            "review_type": "security",
            "reviewer_role": "fac_reviewer",
            "started_at": "2026-02-10T00:00:00Z",
            "status": "alive",
            "terminal_reason": null,
            "model_id": "gpt-5.3-codex",
            "backend_id": "codex",
            "restart_count": 1,
            "sequence_number": 3,
            "previous_run_id": null,
            "previous_head_sha": null,
            "pid": dead_pid_for_test(),
            "proc_start_time": 987_654_321,
            "integrity_hmac": "deadbeef"
        });
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&legacy).expect("serialize legacy state"),
        )
        .expect("write legacy run-state");

        let loaded = load_review_run_state_for_home(home, 441, "security").expect("load run-state");
        match loaded {
            ReviewRunStateLoad::Present(found) => {
                assert_eq!(found.owner_repo, "example/repo");
                assert!(found.integrity_hmac.is_some());
            },
            other => panic!("expected migrated present state, got {other:?}"),
        }

        let persisted = std::fs::read_to_string(&path).expect("read migrated state");
        assert!(
            persisted.contains("\"owner_repo\""),
            "migrated state must include owner_repo"
        );
        assert!(
            !persisted.contains("\"pr_url\""),
            "migrated state must drop legacy pr_url field"
        );

        let verified =
            load_review_run_state_verified_for_home(home, 441, "security").expect("load verified");
        assert!(
            matches!(verified, ReviewRunStateLoad::Present(_)),
            "migrated state must pass integrity verification"
        );
    }

    #[test]
    fn test_review_run_state_schema_fields_stable() {
        let value = serde_json::to_value(sample_state()).expect("serialize");
        assert_eq!(
            value
                .get("run_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "pr441-security-s3-01234567"
        );
        assert_eq!(
            value
                .get("review_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "security"
        );
        assert_eq!(
            value
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "alive"
        );
        assert!(
            value.get("sequence_number").is_some(),
            "sequence_number field must exist"
        );
    }

    #[test]
    fn test_review_run_state_missing_is_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let loaded = load_review_run_state_for_home(home, 999, "quality").expect("load run-state");
        match loaded {
            ReviewRunStateLoad::Missing { path } => {
                assert_eq!(path, review_run_state_path_for_home(home, 999, "quality"));
            },
            other => panic!("expected missing state, got {other:?}"),
        }
    }

    #[test]
    fn test_review_run_state_corrupt_is_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let path = review_run_state_path_for_home(home, 77, "security");
        std::fs::create_dir_all(path.parent().expect("path parent")).expect("create dir");
        std::fs::write(&path, "{not-json").expect("write corrupt json");
        let loaded = load_review_run_state_for_home(home, 77, "security").expect("load run-state");
        match loaded {
            ReviewRunStateLoad::Corrupt { path: found, error } => {
                assert_eq!(found, path);
                assert!(error.contains("parse"), "unexpected error detail: {error}");
            },
            other => panic!("expected corrupt state, got {other:?}"),
        }
    }

    #[test]
    fn test_review_run_state_ambiguous_is_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state = sample_state();
        let path = review_run_state_path_for_home(home, 441, "security");
        write_review_run_state_to_path(&path, &state).expect("write state");
        let alt = path.parent().expect("parent dir").join("state.backup.json");
        write_review_run_state_to_path(&alt, &state).expect("write secondary state");
        let loaded = load_review_run_state_for_home(home, 441, "security").expect("load run-state");
        match loaded {
            ReviewRunStateLoad::Ambiguous { candidates, .. } => {
                assert_eq!(candidates.len(), 2);
            },
            other => panic!("expected ambiguous state, got {other:?}"),
        }
    }

    #[test]
    fn test_next_sequence_number_reconstructs_from_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state = sample_state();
        write_review_run_state_for_home(home, &state).expect("write run-state");
        let next =
            next_review_sequence_number_for_home(home, 441, "security").expect("next sequence");
        assert_eq!(next, 4);
    }

    #[test]
    fn test_try_acquire_review_lease_for_home_is_scoped_and_contentious() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let owner_repo = "example/repo";
        let pr_number = 441;
        let review_type = "security";

        let first = try_acquire_review_lease_for_home(home, owner_repo, pr_number, review_type)
            .expect("first lease attempt")
            .expect("first lease should be acquired");
        let lock_path =
            review_lock_path_for_home(home, owner_repo, pr_number, review_type).expect("path");
        assert!(
            lock_path.starts_with(home),
            "lock path must stay under provided home: {}",
            lock_path.display()
        );
        assert!(lock_path.exists(), "lock file should exist");

        let second = try_acquire_review_lease_for_home(home, owner_repo, pr_number, review_type)
            .expect("second lease attempt");
        assert!(
            second.is_none(),
            "second lease attempt must observe contention"
        );

        drop(first);
        let mut third = None;
        for _ in 0..10 {
            third = try_acquire_review_lease_for_home(home, owner_repo, pr_number, review_type)
                .expect("third lease attempt");
            if third.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            third.is_some(),
            "lease should be re-acquirable after release"
        );
    }

    #[test]
    fn test_load_review_run_state_strict_fails_closed_for_corrupt_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let path = review_run_state_path_for_home(home, 441, "quality");
        std::fs::create_dir_all(path.parent().expect("path parent")).expect("create dir");
        std::fs::write(&path, "{\"run_id\":").expect("write corrupt json");
        let error = load_review_run_state_strict_for_home(home, 441, "quality")
            .expect_err("must fail closed");
        assert!(
            error.contains("corrupt-state"),
            "unexpected error detail: {error}"
        );
    }

    #[test]
    fn test_load_review_run_state_normalizes_legacy_verdict_termination_reason() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let mut state = sample_state();
        state.status = ReviewRunStatus::Failed;
        state.terminal_reason = Some(TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED_LEGACY.to_string());
        state.pid = None;
        state.proc_start_time = None;
        state.integrity_hmac = None;
        write_review_run_state_for_home(home, &state).expect("write legacy-style terminal state");

        let loaded = load_review_run_state_for_home(home, 441, "security").expect("load state");
        match loaded {
            ReviewRunStateLoad::Present(found) => {
                assert_eq!(found.status, ReviewRunStatus::Done);
                assert_eq!(
                    found.terminal_reason.as_deref(),
                    Some(TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED)
                );
            },
            other => panic!("expected normalized state, got {other:?}"),
        }
    }

    #[test]
    fn test_load_review_run_state_verified_rejects_dead_pid_without_integrity_hmac() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let mut state = sample_state();
        state.pid = Some(dead_pid_for_test());
        state.proc_start_time = Some(987_654_321);
        state.integrity_hmac = None;
        let path = review_run_state_path_for_home(home, 441, "security");
        write_review_run_state_to_path(&path, &state).expect("write run-state without integrity");

        let loaded =
            load_review_run_state_verified_for_home(home, 441, "security").expect("load verified");
        match loaded {
            ReviewRunStateLoad::Corrupt { error, .. } => {
                assert!(
                    error.contains("integrity"),
                    "expected integrity verification failure, got: {error}"
                );
            },
            other => panic!("expected corrupt state, got {other:?}"),
        }
    }

    #[test]
    fn test_load_review_run_state_verified_rejects_live_pid_without_integrity_hmac() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn persistent child");
        let pid = child.id();
        let proc_start_time = get_process_start_time(pid).expect("read process start time");

        let mut state = sample_state();
        state.pid = Some(pid);
        state.proc_start_time = Some(proc_start_time);
        state.integrity_hmac = None;
        let path = review_run_state_path_for_home(home, 441, "security");
        write_review_run_state_to_path(&path, &state).expect("write run-state without integrity");

        let loaded =
            load_review_run_state_verified_for_home(home, 441, "security").expect("load verified");
        match loaded {
            ReviewRunStateLoad::Corrupt { error, .. } => {
                assert!(
                    error.contains("integrity"),
                    "expected integrity verification failure, got: {error}"
                );
            },
            other => panic!("expected corrupt state, got {other:?}"),
        }

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn test_load_review_run_state_verified_accepts_dead_pid_with_integrity_hmac() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let mut state = sample_state();
        state.pid = Some(dead_pid_for_test());
        state.proc_start_time = Some(987_654_321);
        write_review_run_state_for_home(home, &state).expect("write integrity-bound run-state");

        let loaded =
            load_review_run_state_verified_for_home(home, 441, "security").expect("load verified");
        match loaded {
            ReviewRunStateLoad::Present(found) => {
                assert!(
                    found.integrity_hmac.is_some(),
                    "integrity binding must be present"
                );
                assert_eq!(found.pid, state.pid);
                assert_eq!(found.proc_start_time, state.proc_start_time);
            },
            other => panic!("expected present state, got {other:?}"),
        }
    }

    // ── list_review_pr_numbers deterministic retention tests ─────────────

    #[test]
    fn test_list_review_pr_numbers_returns_sorted_unique() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        for pr in [10, 5, 20, 15, 5] {
            fs::create_dir_all(root.join(pr.to_string())).expect("mkdir");
        }
        // Also create a non-numeric entry that should be ignored.
        fs::create_dir_all(root.join("not-a-number")).expect("mkdir");

        let result = list_review_pr_numbers_from_dir(root, 100, 100).expect("list");
        assert_eq!(result, vec![5, 10, 15, 20]);
    }

    #[test]
    fn test_list_review_pr_numbers_empty_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let result = list_review_pr_numbers_from_dir(temp.path(), 100, 100).expect("list");
        assert!(result.is_empty());
    }

    #[test]
    fn test_list_review_pr_numbers_nonexistent_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let result = list_review_pr_numbers_from_dir(&temp.path().join("does-not-exist"), 100, 100)
            .expect("list");
        assert!(result.is_empty());
    }

    #[test]
    fn test_list_review_pr_numbers_retain_cap_keeps_highest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        // Create PR directories 1..=20.
        for pr in 1..=20u32 {
            fs::create_dir_all(root.join(pr.to_string())).expect("mkdir");
        }
        // Retain only the top 5 — should keep 16, 17, 18, 19, 20.
        let result = list_review_pr_numbers_from_dir(root, 10_000, 5).expect("list");
        assert_eq!(result, vec![16, 17, 18, 19, 20]);
    }

    #[test]
    fn test_list_review_pr_numbers_scan_cap_limits_entries() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        // Create 30 PR directories.
        for pr in 1..=30u32 {
            fs::create_dir_all(root.join(pr.to_string())).expect("mkdir");
        }
        // Scan only 10 entries — we get at most 10 PRs.
        // The specific PRs depend on filesystem order, but the result
        // must be sorted and deterministic for a given filesystem state.
        let result = list_review_pr_numbers_from_dir(root, 10, 10_000).expect("list");
        assert!(result.len() <= 10, "should scan at most 10 entries");
        // Verify the result is sorted.
        let mut sorted = result.clone();
        sorted.sort_unstable();
        assert_eq!(result, sorted, "result must be sorted");
    }

    #[test]
    fn test_list_review_pr_numbers_retain_cap_deterministic() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        // Create PR directories 100..=200.
        for pr in 100..=200u32 {
            fs::create_dir_all(root.join(pr.to_string())).expect("mkdir");
        }
        // Retain top 10 — always 191..=200 regardless of filesystem order.
        let result = list_review_pr_numbers_from_dir(root, 10_000, 10).expect("list");
        assert_eq!(
            result,
            (191..=200).collect::<Vec<u32>>(),
            "must deterministically retain highest PR numbers"
        );
    }
}
