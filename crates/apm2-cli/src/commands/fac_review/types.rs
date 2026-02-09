//! Shared types, constants, and utility functions for FAC review orchestration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

// ── Duration / count constants ──────────────────────────────────────────────

pub const EVENT_ROTATE_BYTES: u64 = 10 * 1024 * 1024;
pub const MAX_RESTART_ATTEMPTS: u32 = 3;
pub const PULSE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
pub const LIVENESS_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
pub const STALL_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(90);
pub const TERMINATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const LOOP_SLEEP: std::time::Duration = std::time::Duration::from_millis(1000);
pub const COMMENT_CONFIRM_MAX_PAGES: usize = 20;
pub const COMMENT_CONFIRM_MAX_ATTEMPTS: usize = 20;
pub const COMMENT_PERMISSION_SCAN_LINES: usize = 200;
pub const DISPATCH_PENDING_TTL: std::time::Duration = std::time::Duration::from_secs(120);
pub const MAX_EVENT_PAYLOAD_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_PROVIDER_SLOT_COUNT: usize = 10;
pub const PROVIDER_SLOT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);
pub const PROVIDER_SLOT_WAIT_JITTER_MS: u64 = 250;
pub const PROVIDER_BACKOFF_BASE_SECS: u64 = 2;
pub const PROVIDER_BACKOFF_MAX_SECS: u64 = 30;
pub const PROVIDER_BACKOFF_JITTER_MS: u64 = 750;

// ── Path / marker constants ─────────────────────────────────────────────────

pub const SECURITY_PROMPT_PATH: &str = "documents/reviews/SECURITY_REVIEW_PROMPT.md";
pub const QUALITY_PROMPT_PATH: &str = "documents/reviews/CODE_QUALITY_PROMPT.md";
pub const SECURITY_MARKER: &str = "<!-- apm2-review-metadata:v1:security -->";
pub const QUALITY_MARKER: &str = "<!-- apm2-review-metadata:v1:code-quality -->";

// ── Enums ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReviewBackend {
    #[default]
    Codex,
    Gemini,
}

impl ReviewBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Gemini => "gemini",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewRunType {
    All,
    Security,
    Quality,
}

#[derive(Debug, Clone)]
pub struct ReviewModelSelection {
    pub model: String,
    pub backend: ReviewBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewKind {
    Security,
    Quality,
}

impl ReviewKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Quality => "quality",
        }
    }

    pub const fn display(self) -> &'static str {
        match self {
            Self::Security => "Security",
            Self::Quality => "Quality",
        }
    }

    pub const fn prompt_path(self) -> &'static str {
        match self {
            Self::Security => SECURITY_PROMPT_PATH,
            Self::Quality => QUALITY_PROMPT_PATH,
        }
    }

    pub const fn marker(self) -> &'static str {
        match self {
            Self::Security => SECURITY_MARKER,
            Self::Quality => QUALITY_MARKER,
        }
    }
}

// ── Data structs ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewStateEntry {
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub log_file: PathBuf,
    #[serde(default)]
    pub prompt_file: Option<PathBuf>,
    #[serde(default)]
    pub last_message_file: Option<PathBuf>,
    #[serde(default = "default_review_type")]
    pub review_type: String,
    #[serde(default)]
    pub pr_number: u32,
    pub pr_url: String,
    pub head_sha: String,
    #[serde(default)]
    pub restart_count: u32,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default)]
    pub backend: ReviewBackend,
    #[serde(default)]
    pub temp_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReviewStateFile {
    #[serde(default)]
    pub reviewers: BTreeMap<String, ReviewStateEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PulseFile {
    pub head_sha: String,
    pub written_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SingleReviewSummary {
    pub review_type: String,
    pub success: bool,
    pub verdict: String,
    pub model: String,
    pub backend: String,
    pub duration_secs: u64,
    pub restart_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewRunSummary {
    pub pr_url: String,
    pub pr_number: u32,
    pub initial_head_sha: String,
    pub final_head_sha: String,
    pub total_secs: u64,
    pub security: Option<SingleReviewSummary>,
    pub quality: Option<SingleReviewSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DispatchReviewResult {
    pub review_type: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingDispatchEntry {
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DispatchSummary {
    pub pr_url: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub dispatch_epoch: u64,
    pub results: Vec<DispatchReviewResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetriggerSummary {
    pub workflow: String,
    pub repo: String,
    pub pr_number: u32,
    pub dispatched_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BarrierSummary {
    pub repo: String,
    pub event_name: String,
    pub pr_number: u32,
    pub pr_url: String,
    pub head_sha: String,
    pub base_ref: String,
    pub default_branch: String,
    pub author_login: String,
    pub author_association: String,
    pub actor_login: String,
    pub actor_permission: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KickoffSummary {
    pub repo: String,
    pub event_name: String,
    pub pr_number: u32,
    pub pr_url: String,
    pub head_sha: String,
    pub dispatch_epoch: u64,
    pub total_secs: u64,
    pub terminal_state: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectionError {
    pub ts: String,
    pub event: String,
    pub review_type: String,
    pub seq: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectionStatus {
    pub line: String,
    pub sha: String,
    pub current_head_sha: String,
    pub security: String,
    pub quality: String,
    pub recent_events: String,
    pub terminal_failure: bool,
    pub last_seq: u64,
    pub errors: Vec<ProjectionError>,
}

#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub pr_number: u32,
    pub seq: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Debug, Clone)]
pub struct FacEventContext {
    pub repo: String,
    pub event_name: String,
    pub pr_number: u32,
    pub pr_url: String,
    pub head_sha: String,
    pub base_ref: String,
    pub default_branch: String,
    pub author_login: String,
    pub author_association: String,
    pub actor_login: String,
    pub actor_permission: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LivenessSnapshot {
    pub events_since_last: u64,
    pub last_event_type: String,
    pub log_bytes: u64,
    pub made_progress: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ModelPoolEntry {
    pub model: &'static str,
    pub backend: ReviewBackend,
}

#[derive(Debug, Clone)]
pub enum SpawnMode {
    Initial,
    Resume { message: String },
}

#[derive(Debug, Clone)]
pub struct SingleReviewResult {
    pub summary: SingleReviewSummary,
    pub final_head_sha: String,
}

#[derive(Debug, Clone)]
pub struct PostedReview {
    pub id: u64,
    pub verdict: Option<String>,
}

#[derive(Debug)]
pub struct ProviderSlotLease {
    pub _lock_file: std::fs::File,
}

// ── Defaults for serde ──────────────────────────────────────────────────────

pub fn default_model() -> String {
    "gpt-5.3-codex".to_string()
}

pub fn default_review_type() -> String {
    "unknown".to_string()
}

// ── Pure utility functions ──────────────────────────────────────────────────

pub fn now_iso8601_millis() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn now_iso8601() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn parse_pr_url(pr_url: &str) -> Result<(String, u32), String> {
    let trimmed = pr_url.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let without_host = without_scheme
        .strip_prefix("github.com/")
        .ok_or_else(|| format!("invalid GitHub PR URL: {pr_url}"))?;
    let parts = without_host.split('/').collect::<Vec<_>>();
    if parts.len() < 4 || parts[2] != "pull" {
        return Err(format!("invalid GitHub PR URL format: {pr_url}"));
    }
    let pr_number = parts[3]
        .parse::<u32>()
        .map_err(|err| format!("invalid PR number in URL {pr_url}: {err}"))?;
    Ok((format!("{}/{}", parts[0], parts[1]), pr_number))
}

pub fn split_owner_repo(owner_repo: &str) -> Result<(&str, &str), String> {
    let mut parts = owner_repo.split('/');
    let owner = parts
        .next()
        .ok_or_else(|| format!("invalid owner/repo: {owner_repo}"))?;
    let repo = parts
        .next()
        .ok_or_else(|| format!("invalid owner/repo: {owner_repo}"))?;
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return Err(format!("invalid owner/repo: {owner_repo}"));
    }
    Ok((owner, repo))
}

pub fn validate_expected_head_sha(expected: &str) -> Result<(), String> {
    if expected.len() == 40 && expected.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(format!(
        "invalid expected head sha (need 40-hex): {expected}"
    ))
}

pub fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub fn sanitize_for_path(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

pub fn apm2_home_dir() -> Result<PathBuf, String> {
    let base_dirs = directories::BaseDirs::new()
        .ok_or_else(|| "could not resolve home directory".to_string())?;
    Ok(base_dirs.home_dir().join(".apm2"))
}

pub fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Err(format!("path has no parent: {}", path.display()));
    };
    std::fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create parent dir {}: {err}", parent.display()))
}

pub fn entry_pr_number(entry: &ReviewStateEntry) -> Option<u32> {
    if entry.pr_number > 0 {
        Some(entry.pr_number)
    } else {
        parse_pr_url(&entry.pr_url).ok().map(|(_, number)| number)
    }
}
