//! Reducer-first FAC lifecycle authority.
//!
//! This module defines a machine-readable lifecycle model and a single
//! reducer entrypoint for PR/SHA lifecycle transitions and agent lifecycle
//! bookkeeping.

use std::collections::BTreeMap;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, id as current_process_id};

use chrono::{DateTime, Duration, Utc};
use clap::ValueEnum;
use fs2::FileExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_jcs;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::projection::fetch_pr_head_sha_authoritative;
use super::target::resolve_pr_target;
use super::types::{
    TerminationAuthority, apm2_home_dir, ensure_parent_dir,
    normalize_decision_dimension as normalize_verdict_dimension, now_iso8601, sanitize_for_path,
    validate_expected_head_sha,
};
use super::{dispatch, projection_store, state, verdict_projection};
use crate::exit_codes::codes as exit_codes;

const MACHINE_SCHEMA: &str = "apm2.fac.lifecycle_machine.v1";
const PR_STATE_SCHEMA: &str = "apm2.fac.lifecycle_state.v1";
const AGENT_REGISTRY_SCHEMA: &str = "apm2.fac.agent_registry.v1";
const RECOVER_SUMMARY_SCHEMA: &str = "apm2.fac.recover_summary.v1";
const MAX_EVENT_HISTORY: usize = 256;
const MAX_ACTIVE_AGENTS_PER_PR: usize = 2;
const MAX_REGISTRY_ENTRIES: usize = 4096;
const MAX_ERROR_BUDGET: u32 = 10;
const DEFAULT_RETRY_BUDGET: u32 = 3;
const REGISTRY_NON_ACTIVE_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const DEFAULT_TOKEN_TTL_SECS: i64 = 3600;
const PR_STATE_INTEGRITY_ROLE: &str = "pr_state";
const REGISTRY_INTEGRITY_ROLE: &str = "agent_registry";
const RUN_SECRET_MAX_FILE_BYTES: u64 = 128;
const RUN_SECRET_LEN_BYTES: usize = 32;
const RUN_SECRET_MAX_ENCODED_CHARS: usize = 128;
const LIFECYCLE_HMAC_ERROR: &str = "lifecycle state integrity check failed";
type HmacSha256 = Hmac<Sha256>;

pub(super) const fn default_retry_budget() -> u32 {
    DEFAULT_RETRY_BUDGET
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrLifecycleState {
    Untracked,
    Pushed,
    GatesRunning,
    GatesPassed,
    GatesFailed,
    ReviewsDispatched,
    ReviewInProgress,
    VerdictPending,
    VerdictApprove,
    VerdictDeny,
    MergeReady,
    Stuck,
    Stale,
    Recovering,
    Quarantined,
}

impl PrLifecycleState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Untracked => "untracked",
            Self::Pushed => "pushed",
            Self::GatesRunning => "gates_running",
            Self::GatesPassed => "gates_passed",
            Self::GatesFailed => "gates_failed",
            Self::ReviewsDispatched => "reviews_dispatched",
            Self::ReviewInProgress => "review_in_progress",
            Self::VerdictPending => "verdict_pending",
            Self::VerdictApprove => "verdict_approve",
            Self::VerdictDeny => "verdict_deny",
            Self::MergeReady => "merge_ready",
            Self::Stuck => "stuck",
            Self::Stale => "stale",
            Self::Recovering => "recovering",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Implementer,
    ReviewerSecurity,
    ReviewerQuality,
    Orchestrator,
    GateExecutor,
}

impl AgentType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Implementer => "implementer",
            Self::ReviewerSecurity => "reviewer_security",
            Self::ReviewerQuality => "reviewer_quality",
            Self::Orchestrator => "orchestrator",
            Self::GateExecutor => "gate_executor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VerdictValueArg {
    Approve,
    Deny,
}

impl VerdictValueArg {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrackedAgentState {
    Dispatched,
    Running,
    Completed,
    Crashed,
    Reaped,
    Stuck,
}

impl TrackedAgentState {
    const fn is_active(self) -> bool {
        matches!(self, Self::Dispatched | Self::Running)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Crashed => "crashed",
            Self::Reaped => "reaped",
            Self::Stuck => "stuck",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PrLifecycleSnapshot {
    pub owner_repo: String,
    pub pr_number: u32,
    pub current_sha: String,
    pub pr_state: String,
    pub updated_at: String,
    pub time_in_state_seconds: i64,
    pub error_budget_used: u32,
    pub retry_budget_remaining: u32,
    pub last_event_seq: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRegistrySnapshotEntry {
    pub owner_repo: String,
    pub pr_number: u32,
    pub agent_type: String,
    pub state: String,
    pub run_id: String,
    pub sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub pid_alive: bool,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_summary: Option<String>,
    pub completion_token_hash: String,
    pub completion_token_expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRegistrySnapshot {
    pub owner_repo: String,
    pub pr_number: u32,
    pub max_active_agents_per_pr: usize,
    pub active_agents: usize,
    pub total_agents: usize,
    pub entries: Vec<AgentRegistrySnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEvent {
    pub seq: u64,
    pub ts: String,
    pub sha: String,
    pub event: String,
    #[serde(default)]
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrLifecycleRecord {
    pub schema: String,
    pub owner_repo: String,
    pub pr_number: u32,
    pub current_sha: String,
    pub pr_state: PrLifecycleState,
    #[serde(default)]
    pub verdicts: BTreeMap<String, String>,
    pub error_budget_used: u32,
    pub retry_budget_remaining: u32,
    pub updated_at: String,
    pub last_event_seq: u64,
    #[serde(default)]
    pub events: Vec<LifecycleEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_hmac: Option<String>,
}

impl PrLifecycleRecord {
    fn new(owner_repo: &str, pr_number: u32, sha: &str) -> Self {
        Self {
            schema: PR_STATE_SCHEMA.to_string(),
            owner_repo: owner_repo.to_ascii_lowercase(),
            pr_number,
            current_sha: sha.to_ascii_lowercase(),
            pr_state: PrLifecycleState::Untracked,
            verdicts: BTreeMap::new(),
            error_budget_used: 0,
            retry_budget_remaining: DEFAULT_RETRY_BUDGET,
            updated_at: now_iso8601(),
            last_event_seq: 0,
            events: Vec::new(),
            integrity_hmac: None,
        }
    }

    fn append_event(&mut self, sha: &str, event: &str, detail: serde_json::Value) {
        self.last_event_seq = self.last_event_seq.saturating_add(1);
        self.updated_at = now_iso8601();
        self.events.push(LifecycleEvent {
            seq: self.last_event_seq,
            ts: self.updated_at.clone(),
            sha: sha.to_ascii_lowercase(),
            event: event.to_string(),
            detail,
        });
        if self.events.len() > MAX_EVENT_HISTORY {
            let excess = self.events.len() - MAX_EVENT_HISTORY;
            self.events.drain(0..excess);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrackedAgent {
    agent_id: String,
    owner_repo: String,
    pr_number: u32,
    sha: String,
    run_id: String,
    agent_type: AgentType,
    state: TrackedAgentState,
    started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proc_start_time: Option<u64>,
    completion_token_hash: String,
    token_expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reap_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRegistry {
    schema: String,
    updated_at: String,
    #[serde(default)]
    entries: Vec<TrackedAgent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    integrity_hmac: Option<String>,
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self {
            schema: AGENT_REGISTRY_SCHEMA.to_string(),
            updated_at: now_iso8601(),
            entries: Vec::new(),
            integrity_hmac: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoverSummary {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    refreshed_identity: bool,
    head_sha: String,
    reaped_agents: usize,
    state: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum LifecycleEventKind {
    PushObserved,
    GatesStarted,
    GatesPassed,
    GatesFailed,
    ReviewsDispatched,
    ReviewerSpawned { review_type: String },
    VerdictSet { dimension: String, decision: String },
    AgentCrashed { agent_type: AgentType },
    ShaDriftDetected,
    RecoverRequested,
    RecoverCompleted,
    Quarantined { reason: String },
    ProjectionFailed { reason: String },
}

impl LifecycleEventKind {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::PushObserved => "push_observed",
            Self::GatesStarted => "gates_started",
            Self::GatesPassed => "gates_passed",
            Self::GatesFailed => "gates_failed",
            Self::ReviewsDispatched => "reviews_dispatched",
            Self::ReviewerSpawned { .. } => "reviewer_spawned",
            Self::VerdictSet { .. } => "verdict_set",
            Self::AgentCrashed { .. } => "agent_crashed",
            Self::ShaDriftDetected => "sha_drift_detected",
            Self::RecoverRequested => "recover_requested",
            Self::RecoverCompleted => "recover_completed",
            Self::Quarantined { .. } => "quarantined",
            Self::ProjectionFailed { .. } => "projection_failed",
        }
    }
}

fn lifecycle_root() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("fac_lifecycle"))
}

fn pr_state_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(lifecycle_root()?
        .join("pr")
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}.json")))
}

fn pr_state_lock_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(lifecycle_root()?
        .join("pr")
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}.lock")))
}

fn machine_artifact_path() -> Result<PathBuf, String> {
    Ok(lifecycle_root()?.join("fac_lifecycle_machine.v1.json"))
}

fn registry_path() -> Result<PathBuf, String> {
    Ok(lifecycle_root()?.join("agent_registry.v1.json"))
}

fn registry_lock_path() -> Result<PathBuf, String> {
    Ok(lifecycle_root()?.join("agent_registry.lock"))
}

fn acquire_registry_lock() -> Result<std::fs::File, String> {
    let lock_path = registry_lock_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open registry lock {}: {err}",
                lock_path.display()
            )
        })?;
    lock_file.lock_exclusive().map_err(|err| {
        format!(
            "failed to acquire registry lock {}: {err}",
            lock_path.display()
        )
    })?;
    Ok(lock_file)
}

fn acquire_pr_state_lock(owner_repo: &str, pr_number: u32) -> Result<std::fs::File, String> {
    let lock_path = pr_state_lock_path(owner_repo, pr_number)?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open lifecycle state lock {}: {err}",
                lock_path.display()
            )
        })?;
    lock_file.lock_exclusive().map_err(|err| {
        format!(
            "failed to acquire lifecycle state lock {}: {err}",
            lock_path.display()
        )
    })?;
    Ok(lock_file)
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("failed to serialize {}: {err}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create temp file: {err}"))?;
    temp.write_all(&payload)
        .map_err(|err| format!("failed to write temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync temp file: {err}"))?;
    temp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

#[derive(Serialize)]
struct PrLifecycleRecordIntegrityBinding<'a> {
    schema: &'a str,
    owner_repo: &'a str,
    pr_number: u32,
    current_sha: &'a str,
    pr_state: &'a str,
    error_budget_used: u32,
    retry_budget_remaining: u32,
    updated_at: &'a str,
    last_event_seq: u64,
    #[serde(default)]
    events: &'a [LifecycleEvent],
}

#[derive(Serialize)]
struct AgentRegistryIntegrityBinding<'a> {
    schema: &'a str,
    updated_at: &'a str,
    #[serde(default)]
    entries: &'a [TrackedAgent],
}

fn registry_entry_ttl() -> Duration {
    let secs = std::env::var("APM2_FAC_REGISTRY_NON_ACTIVE_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(REGISTRY_NON_ACTIVE_TTL_SECS);
    Duration::seconds(secs)
}

fn lifecycle_secrets_dir() -> Result<PathBuf, String> {
    Ok(lifecycle_root()?.join("secrets"))
}

fn pr_state_secret_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(lifecycle_secrets_dir()?
        .join(PR_STATE_INTEGRITY_ROLE)
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}.secret")))
}

fn registry_secret_path() -> Result<PathBuf, String> {
    Ok(lifecycle_secrets_dir()?
        .join(REGISTRY_INTEGRITY_ROLE)
        .join("agent_registry.secret"))
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
                format!("failed to open lifecycle secret {}: {err}", path.display()),
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
                format!("failed to open lifecycle secret {}: {err}", path.display()),
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
                "failed to open lifecycle secret {}: {err}",
                path.display()
            ));
        },
    };
    let size = file
        .metadata()
        .map_err(|err| format!("failed to stat secret {}: {err}", path.display()))?
        .len();
    if size > RUN_SECRET_MAX_FILE_BYTES {
        return Err(format!(
            "lifecycle secret {} exceeds maximum size ({} > {})",
            path.display(),
            size,
            RUN_SECRET_MAX_FILE_BYTES
        ));
    }
    let mut encoded = String::new();
    file.read_to_string(&mut encoded)
        .map_err(|err| format!("failed to read lifecycle secret {}: {err}", path.display()))?;
    let encoded = encoded.trim();
    if encoded.is_empty() {
        return Ok(None);
    }
    if encoded.len() > RUN_SECRET_MAX_ENCODED_CHARS {
        return Err(format!(
            "lifecycle secret {} exceeds maximum encoded length",
            path.display()
        ));
    }
    let secret = hex::decode(encoded).map_err(|err| {
        format!(
            "failed to decode lifecycle secret {}: {err}",
            path.display()
        )
    })?;
    if secret.len() != RUN_SECRET_LEN_BYTES {
        return Err(format!(
            "lifecycle secret {} has invalid length {} (expected {})",
            path.display(),
            secret.len(),
            RUN_SECRET_LEN_BYTES
        ));
    }
    Ok(Some(secret))
}

fn write_secret_atomic(path: &Path, encoded_secret: &str) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("lifecycle secret path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create lifecycle secret temp file: {err}"))?;
    #[cfg(unix)]
    {
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to set lifecycle secret temp file mode: {err}"))?;
    }
    temp.write_all(encoded_secret.as_bytes())
        .map_err(|err| format!("failed to write lifecycle secret {}: {err}", path.display()))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync lifecycle secret {}: {err}", path.display()))?;
    temp.persist(path).map_err(|err| {
        format!(
            "failed to persist lifecycle secret {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

fn rotate_secret(path: &Path) -> Result<Vec<u8>, String> {
    let mut secret = [0u8; RUN_SECRET_LEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let encoded = hex::encode(secret);
    write_secret_atomic(path, &encoded)?;
    Ok(secret.to_vec())
}

fn read_or_rotate_secret(path: &Path) -> Result<Vec<u8>, String> {
    read_secret_hex_bytes(path)?.map_or_else(|| rotate_secret(path), Ok)
}

fn pr_state_binding_payload(state: &PrLifecycleRecord) -> Result<Vec<u8>, String> {
    let binding = PrLifecycleRecordIntegrityBinding {
        schema: &state.schema,
        owner_repo: &state.owner_repo,
        pr_number: state.pr_number,
        current_sha: &state.current_sha,
        pr_state: state.pr_state.as_str(),
        error_budget_used: state.error_budget_used,
        retry_budget_remaining: state.retry_budget_remaining,
        updated_at: &state.updated_at,
        last_event_seq: state.last_event_seq,
        events: &state.events,
    };
    serde_jcs::to_vec(&binding)
        .map_err(|err| format!("failed to build lifecycle record integrity payload: {err}"))
}

fn registry_binding_payload(registry: &AgentRegistry) -> Result<Vec<u8>, String> {
    let binding = AgentRegistryIntegrityBinding {
        schema: &registry.schema,
        updated_at: &registry.updated_at,
        entries: &registry.entries,
    };
    serde_jcs::to_vec(&binding)
        .map_err(|err| format!("failed to build registry integrity payload: {err}"))
}

fn compute_hmac(secret: &[u8], payload: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|err| format!("invalid lifecycle integrity secret: {err}"))?;
    mac.update(payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_hmac(stored: &str, computed: &str) -> Result<bool, String> {
    let expected = hex::decode(stored)
        .map_err(|err| format!("invalid lifecycle integrity_hmac encoding: {err}"))?;
    let actual = hex::decode(computed)
        .map_err(|err| format!("invalid lifecycle computed integrity_hmac encoding: {err}"))?;
    if expected.len() != actual.len() {
        return Ok(false);
    }
    Ok(expected.ct_eq(actual.as_slice()).into())
}

fn bind_pr_lifecycle_record_integrity(state: &mut PrLifecycleRecord) -> Result<(), String> {
    let secret = read_or_rotate_secret(&pr_state_secret_path(&state.owner_repo, state.pr_number)?)?;
    let payload = pr_state_binding_payload(state)?;
    let computed = compute_hmac(&secret, &payload)?;
    if let Some(stored) = state.integrity_hmac.as_deref() {
        let matches = verify_hmac(stored, &computed)?;
        if !matches {
            return Err("lifecycle state integrity check failed".to_string());
        }
        return Ok(());
    }
    state.integrity_hmac = Some(computed);
    Ok(())
}

fn verify_pr_lifecycle_record_integrity_without_rotation(
    state: &PrLifecycleRecord,
) -> Result<(), String> {
    let Some(stored) = state.integrity_hmac.as_deref() else {
        return Ok(());
    };
    let secret = read_secret_hex_bytes(&pr_state_secret_path(&state.owner_repo, state.pr_number)?)?
        .ok_or_else(|| {
            format!(
                "missing lifecycle integrity secret for {} PR #{}",
                state.owner_repo, state.pr_number
            )
        })?;
    let payload = pr_state_binding_payload(state)?;
    let computed = compute_hmac(&secret, &payload)?;
    let matches = verify_hmac(stored, &computed)?;
    if !matches {
        return Err("lifecycle state integrity check failed".to_string());
    }
    Ok(())
}

fn bind_registry_integrity(registry: &mut AgentRegistry) -> Result<(), String> {
    let secret = read_or_rotate_secret(&registry_secret_path()?)?;
    let payload = registry_binding_payload(registry)?;
    let computed = compute_hmac(&secret, &payload)?;
    if let Some(stored) = registry.integrity_hmac.as_deref() {
        let matches = verify_hmac(stored, &computed)?;
        if !matches {
            return Err("agent registry integrity check failed".to_string());
        }
        return Ok(());
    }
    registry.integrity_hmac = Some(computed);
    Ok(())
}

fn verify_registry_integrity_without_rotation(registry: &AgentRegistry) -> Result<(), String> {
    let Some(stored) = registry.integrity_hmac.as_deref() else {
        return Ok(());
    };
    let secret = read_secret_hex_bytes(&registry_secret_path()?)?
        .ok_or_else(|| "missing agent registry integrity secret".to_string())?;
    let payload = registry_binding_payload(registry)?;
    let computed = compute_hmac(&secret, &payload)?;
    let matches = verify_hmac(stored, &computed)?;
    if !matches {
        return Err("agent registry integrity check failed".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn process_parent_pid(pid: u32) -> Option<u32> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat_content = fs::read_to_string(stat_path).ok()?;
    let (_, tail) = stat_content.rsplit_once(") ")?;
    tail.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(unix)]
fn is_descendant_of_pid(child_pid: u32, ancestor_pid: u32) -> bool {
    if child_pid == 0 || ancestor_pid == 0 {
        return false;
    }
    if child_pid == ancestor_pid {
        return true;
    }
    let mut cursor = child_pid;
    for _ in 0..256 {
        let Some(parent) = process_parent_pid(cursor) else {
            return false;
        };
        if parent == ancestor_pid {
            return true;
        }
        cursor = parent;
    }
    false
}

#[cfg(not(unix))]
fn is_descendant_of_pid(_child_pid: u32, _ancestor_pid: u32) -> bool {
    false
}

const fn is_authoritative_sha_event(event: &LifecycleEventKind) -> bool {
    matches!(
        event,
        LifecycleEventKind::PushObserved | LifecycleEventKind::GatesPassed
    )
}

fn is_sha_ancestor(ancestor_sha: &str, descendant_sha: &str) -> Option<bool> {
    let output = Command::new("git")
        .args(["merge-base", "--is-ancestor", ancestor_sha, descendant_sha])
        .output()
        .ok()?;
    match output.status.code() {
        Some(0) => Some(true),
        Some(1) => Some(false),
        _ => None,
    }
}

fn classify_sha_drift(event_sha: &str, current_sha: &str) -> (&'static str, &'static str) {
    match is_sha_ancestor(event_sha, current_sha) {
        Some(true) => ("sha_ancestor", "event sha is an ancestor of current sha"),
        Some(false) => (
            "sha_divergent",
            "event sha is not an ancestor of current sha",
        ),
        None => ("sha_relation_unknown", "unable to establish sha order"),
    }
}

fn is_pr_state_corruption_error(err: &str) -> bool {
    err == LIFECYCLE_HMAC_ERROR
        || err.starts_with("failed to parse lifecycle state")
        || err.starts_with("unexpected lifecycle state schema")
        || err.starts_with("lifecycle state identity mismatch")
        || err.starts_with("lifecycle state owner mismatch")
}

fn pr_state_quarantine_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    let state_parent = pr_state_path(owner_repo, pr_number)?
        .parent()
        .ok_or_else(|| {
            format!("lifecycle state path has no parent for PR #{pr_number} in {owner_repo}",)
        })?
        .join(".quarantine");
    ensure_parent_dir(&state_parent)?;
    let stamp = Utc::now().timestamp_millis();
    for attempt in 0..64 {
        let path = state_parent.join(format!("pr-{pr_number}.{stamp}.{attempt}.json.quarantine"));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(format!(
        "failed to allocate lifecycle quarantine path for PR #{} in {}",
        pr_number,
        state_parent.display()
    ))
}

fn quarantine_pr_state(owner_repo: &str, pr_number: u32) -> Result<Option<PathBuf>, String> {
    let path = pr_state_path(owner_repo, pr_number)?;
    if !path.exists() {
        return Ok(None);
    }
    let quarantine = pr_state_quarantine_path(owner_repo, pr_number)?;
    fs::rename(&path, &quarantine).map_err(|err| {
        format!(
            "failed to quarantine lifecycle state {} -> {}: {err}",
            path.display(),
            quarantine.display()
        )
    })?;
    Ok(Some(quarantine))
}

fn new_pr_state(owner_repo: &str, pr_number: u32, sha: &str) -> Result<PrLifecycleRecord, String> {
    let mut state = PrLifecycleRecord::new(owner_repo, pr_number, sha);
    bind_pr_lifecycle_record_integrity(&mut state)?;
    Ok(state)
}

fn load_pr_state_with_recovery(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    recover_on_corrupt: bool,
) -> Result<PrLifecycleRecord, String> {
    let path = pr_state_path(owner_repo, pr_number)?;
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return new_pr_state(owner_repo, pr_number, sha);
        },
        Err(err) => {
            return Err(format!(
                "failed to read lifecycle state {}: {err}",
                path.display()
            ));
        },
    };
    let mut parsed: PrLifecycleRecord = match serde_json::from_slice(&bytes) {
        Ok(state) => state,
        Err(err) => {
            let err = format!("failed to parse lifecycle state {}: {err}", path.display());
            if recover_on_corrupt {
                if is_pr_state_corruption_error(&err) {
                    if let Err(quarantine_err) = quarantine_pr_state(owner_repo, pr_number) {
                        return Err(format!(
                            "{err}; failed to quarantine corrupt state: {quarantine_err}"
                        ));
                    }
                    return new_pr_state(owner_repo, pr_number, sha);
                }
            } else if is_pr_state_corruption_error(&err) {
                let _ = quarantine_pr_state(owner_repo, pr_number);
            }
            return Err(err);
        },
    };
    if parsed.schema != PR_STATE_SCHEMA {
        let err = format!(
            "unexpected lifecycle state schema {} at {}",
            parsed.schema,
            path.display()
        );
        if recover_on_corrupt && is_pr_state_corruption_error(&err) {
            if let Err(quarantine_err) = quarantine_pr_state(owner_repo, pr_number) {
                return Err(format!(
                    "{err}; failed to quarantine corrupt state: {quarantine_err}"
                ));
            }
            return new_pr_state(owner_repo, pr_number, sha);
        }
        if is_pr_state_corruption_error(&err) {
            let _ = quarantine_pr_state(owner_repo, pr_number);
        }
        return Err(err);
    }
    parsed.owner_repo = parsed.owner_repo.to_ascii_lowercase();
    if parsed.pr_number != pr_number {
        let err = format!(
            "lifecycle state identity mismatch for {}: expected pr={}, got pr={}",
            path.display(),
            pr_number,
            parsed.pr_number
        );
        if recover_on_corrupt && is_pr_state_corruption_error(&err) {
            if let Err(quarantine_err) = quarantine_pr_state(owner_repo, pr_number) {
                return Err(format!(
                    "{err}; failed to quarantine corrupt state: {quarantine_err}"
                ));
            }
            return new_pr_state(owner_repo, pr_number, sha);
        }
        if is_pr_state_corruption_error(&err) {
            let _ = quarantine_pr_state(owner_repo, pr_number);
        }
        return Err(err);
    }
    if let Err(err) = bind_pr_lifecycle_record_integrity(&mut parsed) {
        if err == LIFECYCLE_HMAC_ERROR {
            if recover_on_corrupt {
                if let Err(quarantine_err) = quarantine_pr_state(owner_repo, pr_number) {
                    return Err(format!(
                        "{err}; failed to quarantine corrupt state: {quarantine_err}"
                    ));
                }
                return new_pr_state(owner_repo, pr_number, sha);
            }
            if is_pr_state_corruption_error(&err) {
                let _ = quarantine_pr_state(owner_repo, pr_number);
            }
            return Err(err);
        }
        return Err(err);
    }
    Ok(parsed)
}

fn prune_registry_stale_non_active_entries(registry: &mut AgentRegistry) -> usize {
    let cutoff = Utc::now() - registry_entry_ttl();
    let before = registry.entries.len();
    registry.entries.retain(|entry| {
        if entry.state.is_active() {
            return true;
        }
        if let Some(seen) = entry
            .completed_at
            .as_deref()
            .map_or_else(|| parse_utc(&entry.started_at), parse_utc)
        {
            return seen >= cutoff;
        }
        false
    });
    before.saturating_sub(registry.entries.len())
}

fn prune_registry_to_entry_limit(registry: &mut AgentRegistry) -> usize {
    if registry.entries.len() <= MAX_REGISTRY_ENTRIES {
        return 0;
    }
    let active_count = registry
        .entries
        .iter()
        .filter(|entry| entry.state.is_active())
        .count();
    let keep_non_active = MAX_REGISTRY_ENTRIES.saturating_sub(active_count);
    let mut non_active: Vec<(DateTime<Utc>, usize)> = registry
        .entries
        .iter()
        .enumerate()
        .filter_map(|(idx, entry)| {
            if entry.state.is_active() {
                return None;
            }
            let last_seen = entry
                .completed_at
                .as_deref()
                .and_then(parse_utc)
                .or_else(|| parse_utc(&entry.started_at))
                .unwrap_or_else(Utc::now);
            Some((last_seen, idx))
        })
        .collect();
    if non_active.len() <= keep_non_active {
        return 0;
    }
    non_active.sort_unstable_by_key(|(seen, _)| *seen);
    let mut keep = std::collections::BTreeSet::new();
    for (_, idx) in non_active.iter().rev().take(keep_non_active) {
        keep.insert(*idx);
    }
    let before = registry.entries.len();
    let entries = std::mem::take(&mut registry.entries);
    registry.entries = entries
        .into_iter()
        .enumerate()
        .filter_map(|(idx, entry)| {
            if entry.state.is_active() || keep.contains(&idx) {
                Some(entry)
            } else {
                None
            }
        })
        .collect();
    before.saturating_sub(registry.entries.len())
}

fn apply_registry_retention(registry: &mut AgentRegistry) {
    let reaped = reap_registry_stale_entries(registry);
    let stale = prune_registry_stale_non_active_entries(registry);
    let excess = prune_registry_to_entry_limit(registry);
    if reaped + stale + excess > 0 {
        registry.updated_at = now_iso8601();
    }
}

fn load_pr_state(owner_repo: &str, pr_number: u32, sha: &str) -> Result<PrLifecycleRecord, String> {
    load_pr_state_with_recovery(owner_repo, pr_number, sha, false)
}

fn load_pr_state_for_readonly(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<PrLifecycleRecord>, String> {
    let path = pr_state_path(owner_repo, pr_number)?;
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to read lifecycle state {}: {err}",
                path.display()
            ));
        },
    };

    let record = serde_json::from_slice::<PrLifecycleRecord>(&bytes)
        .map_err(|err| format!("failed to parse lifecycle state {}: {err}", path.display()))?;
    if record.schema != PR_STATE_SCHEMA {
        return Err(format!(
            "unexpected lifecycle state schema {} at {}",
            record.schema,
            path.display()
        ));
    }
    if !record.owner_repo.eq_ignore_ascii_case(owner_repo) {
        return Err(format!(
            "lifecycle state owner mismatch at {}: expected {owner_repo}, got {}",
            path.display(),
            record.owner_repo
        ));
    }
    if record.pr_number != pr_number {
        return Err(format!(
            "lifecycle state PR mismatch at {}: expected #{pr_number}, got #{}",
            path.display(),
            record.pr_number
        ));
    }

    validate_expected_head_sha(&record.current_sha)?;
    verify_pr_lifecycle_record_integrity_without_rotation(&record)?;
    Ok(Some(record))
}

pub fn load_pr_lifecycle_snapshot(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<PrLifecycleSnapshot>, String> {
    let Some(record) = load_pr_state_for_readonly(owner_repo, pr_number)? else {
        return Ok(None);
    };

    let time_in_state_seconds = parse_utc(&record.updated_at).map_or(0, |updated_at| {
        (Utc::now() - updated_at)
            .to_std()
            .ok()
            .map_or(0, |duration| duration.as_secs().try_into().unwrap_or(0))
    });

    Ok(Some(PrLifecycleSnapshot {
        owner_repo: record.owner_repo,
        pr_number: record.pr_number,
        current_sha: record.current_sha,
        pr_state: record.pr_state.as_str().to_string(),
        updated_at: record.updated_at,
        time_in_state_seconds,
        error_budget_used: record.error_budget_used,
        retry_budget_remaining: record.retry_budget_remaining,
        last_event_seq: record.last_event_seq,
    }))
}

fn load_pr_state_for_recover(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    force: bool,
) -> Result<PrLifecycleRecord, String> {
    if force {
        let _ = quarantine_pr_state(owner_repo, pr_number);
        return new_pr_state(owner_repo, pr_number, sha);
    }
    match load_pr_state_with_recovery(owner_repo, pr_number, sha, true) {
        Ok(state) => Ok(state),
        Err(err) => {
            if is_pr_state_corruption_error(&err) {
                if let Err(quarantine_err) = quarantine_pr_state(owner_repo, pr_number) {
                    return Err(format!(
                        "{err}; failed to quarantine corrupt state: {quarantine_err}"
                    ));
                }
                return new_pr_state(owner_repo, pr_number, sha);
            }
            Err(err)
        },
    }
}

fn save_pr_state(state: &PrLifecycleRecord) -> Result<PathBuf, String> {
    let mut record = state.clone();
    record.integrity_hmac = None;
    bind_pr_lifecycle_record_integrity(&mut record)?;
    let path = pr_state_path(&record.owner_repo, record.pr_number)?;
    atomic_write_json(&path, &record)?;
    Ok(path)
}

fn load_registry() -> Result<AgentRegistry, String> {
    let path = registry_path()?;
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AgentRegistry::default());
        },
        Err(err) => {
            return Err(format!(
                "failed to read agent registry {}: {err}",
                path.display()
            ));
        },
    };
    let mut parsed: AgentRegistry = serde_json::from_slice(&bytes)
        .map_err(|err| format!("failed to parse agent registry {}: {err}", path.display()))?;
    if parsed.schema != AGENT_REGISTRY_SCHEMA {
        return Err(format!(
            "unexpected agent registry schema {} at {}",
            parsed.schema,
            path.display()
        ));
    }
    bind_registry_integrity(&mut parsed)?;
    apply_registry_retention(&mut parsed);
    parsed.updated_at = now_iso8601();
    Ok(parsed)
}

fn load_registry_without_integrity_mutation() -> Result<AgentRegistry, String> {
    let path = registry_path()?;
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AgentRegistry::default());
        },
        Err(err) => {
            return Err(format!(
                "failed to read agent registry {}: {err}",
                path.display()
            ));
        },
    };
    let parsed: AgentRegistry = serde_json::from_slice(&bytes)
        .map_err(|err| format!("failed to parse agent registry {}: {err}", path.display()))?;
    if parsed.schema != AGENT_REGISTRY_SCHEMA {
        return Err(format!(
            "unexpected agent registry schema {} at {}",
            parsed.schema,
            path.display()
        ));
    }
    verify_registry_integrity_without_rotation(&parsed)?;
    Ok(parsed)
}

pub fn load_agent_registry_snapshot_for_pr(
    owner_repo: &str,
    pr_number: u32,
) -> Result<AgentRegistrySnapshot, String> {
    let registry = load_registry_without_integrity_mutation()?;
    let owner_repo = owner_repo.to_ascii_lowercase();

    let mut entries = Vec::new();
    let mut active_agents = 0usize;
    for entry in registry.entries.iter().filter(|entry| {
        entry.owner_repo.eq_ignore_ascii_case(&owner_repo) && entry.pr_number == pr_number
    }) {
        if entry.state.is_active() {
            active_agents = active_agents.saturating_add(1);
        }
        let pid_alive = entry.pid.is_some_and(state::is_process_alive);
        entries.push(AgentRegistrySnapshotEntry {
            owner_repo: entry.owner_repo.clone(),
            pr_number: entry.pr_number,
            agent_type: entry.agent_type.as_str().to_string(),
            state: entry.state.as_str().to_string(),
            run_id: entry.run_id.clone(),
            sha: entry.sha.clone(),
            pid: entry.pid,
            pid_alive,
            started_at: entry.started_at.clone(),
            completed_at: entry.completed_at.clone(),
            completion_status: entry.completion_status.clone(),
            completion_summary: entry.completion_summary.clone(),
            completion_token_hash: entry.completion_token_hash.clone(),
            completion_token_expires_at: entry.token_expires_at.clone(),
        });
    }

    Ok(AgentRegistrySnapshot {
        owner_repo,
        pr_number,
        max_active_agents_per_pr: MAX_ACTIVE_AGENTS_PER_PR,
        active_agents,
        total_agents: entries.len(),
        entries,
    })
}

fn apply_event_to_record(
    record: &mut PrLifecycleRecord,
    sha: &str,
    event: &LifecycleEventKind,
) -> Result<(), String> {
    let sha = sha.to_ascii_lowercase();

    if !record.current_sha.eq_ignore_ascii_case(&sha) {
        record.pr_state = PrLifecycleState::Stale;
        let (relation_code, relation_hint) = classify_sha_drift(&sha, &record.current_sha);
        let is_older_than_current = relation_code == "sha_ancestor";
        record.append_event(
            &sha,
            "sha_drift_detected",
            serde_json::json!({
                "reason": "event_sha_mismatch",
                "authoritative_event": is_authoritative_sha_event(event),
                "relation": relation_code,
                "relation_hint": relation_hint,
            }),
        );

        if is_older_than_current && is_authoritative_sha_event(event) {
            return Err(format!(
                "rejecting lifecycle event {} for PR #{} sha {} because it is older than current sha {} (relation={})",
                event.as_str(),
                record.pr_number,
                sha,
                record.current_sha,
                relation_code
            ));
        }

        if !is_authoritative_sha_event(event) {
            eprintln!(
                "WARNING: ignoring lifecycle event {} for PR #{} sha {} because current sha is {} (relation={})",
                event.as_str(),
                record.pr_number,
                sha,
                record.current_sha,
                relation_code,
            );
            return Ok(());
        }

        if !is_older_than_current {
            record.current_sha.clone_from(&sha);
        }
    }

    match event {
        LifecycleEventKind::VerdictSet {
            dimension,
            decision,
        } => {
            let dim = normalize_verdict_dimension(dimension)?;
            let dec = normalize_verdict_decision(decision)?;
            record.verdicts.insert(dim.to_string(), dec.to_string());
        },
        LifecycleEventKind::ShaDriftDetected => {
            record.current_sha.clone_from(&sha);
        },
        _ => {},
    }

    let next_state = next_state_for_event(record, event)?;
    record.pr_state = next_state;
    if record.pr_state == PrLifecycleState::Stuck {
        record.error_budget_used = record.error_budget_used.saturating_add(1);
        if record.error_budget_used >= MAX_ERROR_BUDGET {
            record.append_event(
                &sha,
                "error_budget_exhausted",
                serde_json::json!({
                    "error_budget_used": record.error_budget_used,
                    "max_error_budget": MAX_ERROR_BUDGET,
                }),
            );
        }
    }
    record.append_event(&sha, event.as_str(), event_detail(event));
    Ok(())
}

fn save_registry(registry: &AgentRegistry) -> Result<PathBuf, String> {
    let mut copy = registry.clone();
    copy.integrity_hmac = None;
    apply_registry_retention(&mut copy);
    bind_registry_integrity(&mut copy)?;
    let path = registry_path()?;
    atomic_write_json(&path, &copy)?;
    Ok(path)
}

fn token_ttl() -> Duration {
    let secs = std::env::var("APM2_FAC_AGENT_REGISTRY_TOKEN_TTL_SECS")
        .ok()
        .or_else(|| std::env::var("APM2_FAC_DONE_TOKEN_TTL_SECS").ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_TOKEN_TTL_SECS);
    Duration::seconds(secs)
}

fn reviewer_agent_type(review_state_type: &str) -> Option<AgentType> {
    match review_state_type {
        "security" => Some(AgentType::ReviewerSecurity),
        "quality" => Some(AgentType::ReviewerQuality),
        _ => None,
    }
}

fn generate_completion_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_utc(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn tracked_agent_id(
    owner_repo: &str,
    pr_number: u32,
    run_id: &str,
    agent_type: AgentType,
) -> String {
    format!(
        "{}::pr{}::{}::{}",
        owner_repo.to_ascii_lowercase(),
        pr_number,
        run_id,
        agent_type.as_str()
    )
}

fn active_agents_for_pr(registry: &AgentRegistry, owner_repo: &str, pr_number: u32) -> usize {
    let owner_repo = owner_repo.to_ascii_lowercase();
    registry
        .entries
        .iter()
        .filter(|entry| entry.owner_repo.eq_ignore_ascii_case(&owner_repo))
        .filter(|entry| entry.pr_number == pr_number)
        .filter(|entry| entry.state.is_active())
        .count()
}

fn reap_registry_stale_entries(registry: &mut AgentRegistry) -> usize {
    let mut reaped = 0usize;
    let stale_without_pid_after = token_ttl() * 2;
    for entry in &mut registry.entries {
        if !entry.state.is_active() {
            continue;
        }

        let mut reap_reason = None;
        if let Some(pid) = entry.pid {
            if !state::is_process_alive(pid) {
                reap_reason = Some("pid_not_alive");
            } else if let Some(expected_start) = entry.proc_start_time {
                let observed = state::get_process_start_time(pid);
                if observed.is_some_and(|value| value != expected_start) {
                    reap_reason = Some("pid_reused");
                }
            }
        } else {
            let started_at = parse_utc(&entry.started_at);
            if started_at
                .and_then(|value| Utc::now().signed_duration_since(value).to_std().ok())
                .is_some_and(|value| value >= stale_without_pid_after.to_std().unwrap_or_default())
            {
                reap_reason = Some("stale_without_pid");
            }
        }

        if let Some(reason) = reap_reason {
            entry.state = TrackedAgentState::Reaped;
            entry.completed_at = Some(now_iso8601());
            entry.reap_reason = Some(reason.to_string());
            reaped = reaped.saturating_add(1);
        }
    }
    if reaped > 0 {
        registry.updated_at = now_iso8601();
    }
    reaped
}

fn normalize_verdict_decision(decision: &str) -> Result<&'static str, String> {
    let normalized = decision.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "approve" => Ok("approve"),
        "deny" => Ok("deny"),
        _ => Err(format!(
            "invalid verdict decision `{decision}` (expected approve|deny)"
        )),
    }
}

fn next_state_for_event(
    state: &PrLifecycleRecord,
    event: &LifecycleEventKind,
) -> Result<PrLifecycleState, String> {
    use PrLifecycleState as S;
    match event {
        LifecycleEventKind::PushObserved => match state.pr_state {
            S::Untracked
            | S::Pushed
            | S::GatesRunning
            | S::GatesPassed
            | S::GatesFailed
            | S::ReviewsDispatched
            | S::ReviewInProgress
            | S::VerdictPending
            | S::VerdictApprove
            | S::VerdictDeny
            | S::MergeReady
            | S::Stuck
            | S::Stale
            | S::Recovering => Ok(S::Pushed),
            S::Quarantined => Err(format!(
                "illegal transition: {} + push_observed",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::GatesStarted => match state.pr_state {
            S::Pushed | S::GatesFailed | S::Recovering => Ok(S::GatesRunning),
            _ => Err(format!(
                "illegal transition: {} + gates_started",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::GatesPassed => match state.pr_state {
            S::GatesRunning => Ok(S::GatesPassed),
            _ => Err(format!(
                "illegal transition: {} + gates_passed",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::GatesFailed => match state.pr_state {
            S::GatesRunning => Ok(S::GatesFailed),
            _ => Err(format!(
                "illegal transition: {} + gates_failed",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::ReviewsDispatched => match state.pr_state {
            S::GatesPassed | S::ReviewsDispatched | S::ReviewInProgress | S::VerdictPending => {
                Ok(S::ReviewsDispatched)
            },
            _ => Err(format!(
                "illegal transition: {} + reviews_dispatched",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::ReviewerSpawned { .. } => match state.pr_state {
            S::ReviewsDispatched | S::ReviewInProgress | S::VerdictPending => {
                Ok(S::ReviewInProgress)
            },
            _ => Err(format!(
                "illegal transition: {} + reviewer_spawned",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::VerdictSet {
            dimension,
            decision,
        } => {
            let _ = normalize_verdict_dimension(dimension)?;
            let normalized_decision = normalize_verdict_decision(decision)?;
            match state.pr_state {
                S::ReviewsDispatched
                | S::ReviewInProgress
                | S::VerdictPending
                | S::VerdictApprove
                | S::VerdictDeny
                | S::MergeReady => {
                    if normalized_decision == "deny" {
                        return Ok(S::VerdictDeny);
                    }
                    if state
                        .verdicts
                        .values()
                        .any(|value| value.eq_ignore_ascii_case("deny"))
                    {
                        return Ok(S::VerdictDeny);
                    }
                    let sec = state
                        .verdicts
                        .get("security")
                        .is_some_and(|value| value.eq_ignore_ascii_case("approve"));
                    let qual = state
                        .verdicts
                        .get("code-quality")
                        .is_some_and(|value| value.eq_ignore_ascii_case("approve"));
                    if sec && qual {
                        Ok(S::MergeReady)
                    } else {
                        Ok(S::VerdictPending)
                    }
                },
                _ => Err(format!(
                    "illegal transition: {} + verdict_set",
                    state.pr_state.as_str()
                )),
            }
        },
        LifecycleEventKind::AgentCrashed { .. } => Ok(S::Stuck),
        LifecycleEventKind::ShaDriftDetected => Ok(S::Stale),
        LifecycleEventKind::RecoverRequested => match state.pr_state {
            S::Stale | S::Stuck | S::Quarantined => Ok(S::Recovering),
            _ => Err(format!(
                "illegal transition: {} + recover_requested",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::RecoverCompleted => match state.pr_state {
            S::Recovering => Ok(S::Pushed),
            _ => Err(format!(
                "illegal transition: {} + recover_completed",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::Quarantined { .. } => Ok(S::Quarantined),
        LifecycleEventKind::ProjectionFailed { .. } => Ok(state.pr_state),
    }
}

fn event_detail(event: &LifecycleEventKind) -> serde_json::Value {
    match event {
        LifecycleEventKind::ReviewerSpawned { review_type } => {
            serde_json::json!({ "review_type": review_type })
        },
        LifecycleEventKind::VerdictSet {
            dimension,
            decision,
        } => serde_json::json!({
            "dimension": dimension,
            "decision": decision,
        }),
        LifecycleEventKind::AgentCrashed { agent_type } => serde_json::json!({
            "agent_type": agent_type.as_str(),
        }),
        LifecycleEventKind::Quarantined { reason }
        | LifecycleEventKind::ProjectionFailed { reason } => serde_json::json!({
            "reason": reason,
        }),
        _ => serde_json::json!({}),
    }
}

pub fn ensure_machine_artifact() -> Result<PathBuf, String> {
    let path = machine_artifact_path()?;
    if path.exists() {
        return Ok(path);
    }
    let transitions = vec![
        serde_json::json!({"from":"untracked|pushed|gates_running|gates_passed|gates_failed|reviews_dispatched|review_in_progress|verdict_pending|verdict_approve|verdict_deny|merge_ready|stuck|stale|recovering","event":"push_observed","to":"pushed"}),
        serde_json::json!({"from":"pushed|gates_failed|recovering","event":"gates_started","to":"gates_running"}),
        serde_json::json!({"from":"gates_running","event":"gates_passed","to":"gates_passed"}),
        serde_json::json!({"from":"gates_running","event":"gates_failed","to":"gates_failed"}),
        serde_json::json!({"from":"gates_passed|reviews_dispatched|review_in_progress|verdict_pending","event":"reviews_dispatched","to":"reviews_dispatched"}),
        serde_json::json!({"from":"reviews_dispatched|review_in_progress|verdict_pending","event":"reviewer_spawned","to":"review_in_progress"}),
        serde_json::json!({"from":"reviews_dispatched|review_in_progress|verdict_pending|verdict_approve|verdict_deny|merge_ready","event":"verdict_set","to":"verdict_pending|verdict_deny|merge_ready"}),
        serde_json::json!({"from":"*","event":"sha_drift_detected","to":"stale"}),
        serde_json::json!({"from":"stale|stuck|quarantined","event":"recover_requested","to":"recovering"}),
        serde_json::json!({"from":"recovering","event":"recover_completed","to":"pushed"}),
    ];
    let machine = serde_json::json!({
        "schema": MACHINE_SCHEMA,
        "generated_at": now_iso8601(),
        "illegal_transition_policy": "fail_closed",
        "states": {
            "pr_lifecycle": [
                "untracked","pushed","gates_running","gates_passed","gates_failed",
                "reviews_dispatched","review_in_progress","verdict_pending",
                "verdict_approve","verdict_deny","merge_ready",
                "stuck","stale","recovering","quarantined"
            ],
            "agent_lifecycle": [
                "dispatched","running","completed","crashed","reaped","stuck"
            ]
        },
        "transitions": transitions
    });
    atomic_write_json(&path, &machine)?;
    Ok(path)
}

pub fn apply_event(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    event: &LifecycleEventKind,
) -> Result<PrLifecycleRecord, String> {
    validate_expected_head_sha(sha)?;
    ensure_machine_artifact()?;
    let _state_lock = acquire_pr_state_lock(owner_repo, pr_number)?;
    let mut record = load_pr_state(owner_repo, pr_number, sha)?;
    apply_event_to_record(&mut record, sha, event)?;
    save_pr_state(&record)?;
    Ok(record)
}

pub fn enforce_pr_capacity(owner_repo: &str, pr_number: u32) -> Result<(), String> {
    let _lock = acquire_registry_lock()?;
    let mut registry = load_registry()?;
    let _ = reap_registry_stale_entries(&mut registry);
    let active = active_agents_for_pr(&registry, owner_repo, pr_number);
    if active >= MAX_ACTIVE_AGENTS_PER_PR {
        save_registry(&registry)?;
        return Err(format!(
            "at_capacity: PR #{pr_number} already has {active} active agents (max={MAX_ACTIVE_AGENTS_PER_PR})"
        ));
    }
    save_registry(&registry)?;
    Ok(())
}

pub fn register_agent_spawn(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    run_id: &str,
    agent_type: AgentType,
    pid: Option<u32>,
    proc_start_time: Option<u64>,
) -> Result<String, String> {
    validate_expected_head_sha(sha)?;
    if run_id.trim().is_empty() {
        return Err("cannot register agent spawn with empty run_id".to_string());
    }

    let _lock = acquire_registry_lock()?;
    let mut registry = load_registry()?;
    let _ = reap_registry_stale_entries(&mut registry);
    let active = active_agents_for_pr(&registry, owner_repo, pr_number);
    if active >= MAX_ACTIVE_AGENTS_PER_PR {
        save_registry(&registry)?;
        return Err(format!(
            "at_capacity: PR #{pr_number} already has {active} active agents (max={MAX_ACTIVE_AGENTS_PER_PR})"
        ));
    }

    let token = generate_completion_token();
    let token_hash = token_hash(&token);
    let expires_at = (Utc::now() + token_ttl()).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let agent_id = tracked_agent_id(owner_repo, pr_number, run_id, agent_type);
    registry.entries.retain(|entry| entry.agent_id != agent_id);
    registry.entries.push(TrackedAgent {
        agent_id,
        owner_repo: owner_repo.to_ascii_lowercase(),
        pr_number,
        sha: sha.to_ascii_lowercase(),
        run_id: run_id.to_string(),
        agent_type,
        state: if pid.is_some() {
            TrackedAgentState::Running
        } else {
            TrackedAgentState::Dispatched
        },
        started_at: now_iso8601(),
        completed_at: None,
        pid,
        proc_start_time,
        completion_token_hash: token_hash,
        token_expires_at: expires_at,
        completion_status: None,
        completion_summary: None,
        reap_reason: None,
    });
    registry.updated_at = now_iso8601();
    save_registry(&registry)?;
    Ok(token)
}

fn mark_registered_agent_reaped(
    owner_repo: &str,
    pr_number: u32,
    run_id: &str,
    agent_type: AgentType,
    reason: &str,
) -> Result<(), String> {
    let _lock = acquire_registry_lock()?;
    let mut registry = load_registry()?;
    let agent_id = tracked_agent_id(owner_repo, pr_number, run_id, agent_type);
    let mut changed = false;
    for entry in &mut registry.entries {
        if entry.agent_id == agent_id {
            entry.state = TrackedAgentState::Reaped;
            entry.completed_at = Some(now_iso8601());
            entry.reap_reason = Some(reason.to_string());
            changed = true;
            break;
        }
    }
    if changed {
        registry.updated_at = now_iso8601();
        save_registry(&registry)?;
    }
    Ok(())
}

fn rollback_registered_reviewer_dispatch(
    owner_repo: &str,
    pr_number: u32,
    run_id: &str,
    agent_type: AgentType,
    pid: Option<u32>,
    reason: &str,
) -> Result<(), String> {
    if let Some(pid) = pid
        && state::is_process_alive(pid)
    {
        dispatch::terminate_process_with_timeout(pid).map_err(|err| {
            format!("failed to terminate spawned reviewer pid={pid} during rollback: {err}")
        })?;
    }
    mark_registered_agent_reaped(owner_repo, pr_number, run_id, agent_type, reason)
}

pub fn register_reviewer_dispatch(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    review_type: &str,
    run_id: Option<&str>,
    pid: Option<u32>,
    proc_start_time: Option<u64>,
) -> Result<Option<String>, String> {
    let agent_type = match review_type {
        "security" => AgentType::ReviewerSecurity,
        "quality" => AgentType::ReviewerQuality,
        _ => return Ok(None),
    };
    let Some(run_id) = run_id else {
        return Ok(None);
    };
    let token = match register_agent_spawn(
        owner_repo,
        pr_number,
        sha,
        run_id,
        agent_type,
        pid,
        proc_start_time,
    ) {
        Ok(token) => token,
        Err(err) => {
            if let Some(pid) = pid
                && state::is_process_alive(pid)
            {
                dispatch::terminate_process_with_timeout(pid).map_err(|kill_err| {
                    format!(
                        "{err}; additionally failed to terminate unregistered reviewer pid={pid}: {kill_err}"
                    )
                })?;
            }
            return Err(err);
        },
    };
    if let Err(err) = apply_event(
        owner_repo,
        pr_number,
        sha,
        &LifecycleEventKind::ReviewsDispatched,
    ) {
        let rollback_reason = "rollback:lifecycle_reviews_dispatched_failed";
        match rollback_registered_reviewer_dispatch(
            owner_repo,
            pr_number,
            run_id,
            agent_type,
            pid,
            rollback_reason,
        ) {
            Ok(()) => return Err(err),
            Err(rollback_err) => {
                return Err(format!(
                    "{err}; additionally failed to rollback registry entry run_id={run_id}: {rollback_err}"
                ));
            },
        }
    }
    if let Err(err) = apply_event(
        owner_repo,
        pr_number,
        sha,
        &LifecycleEventKind::ReviewerSpawned {
            review_type: review_type.to_string(),
        },
    ) {
        let rollback_reason = "rollback:lifecycle_reviewer_spawned_failed";
        match rollback_registered_reviewer_dispatch(
            owner_repo,
            pr_number,
            run_id,
            agent_type,
            pid,
            rollback_reason,
        ) {
            Ok(()) => return Err(err),
            Err(rollback_err) => {
                return Err(format!(
                    "{err}; additionally failed to rollback registry entry run_id={run_id}: {rollback_err}"
                ));
            },
        }
    }
    Ok(Some(token))
}

#[allow(clippy::too_many_arguments)]
pub fn run_verdict_set(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    dimension: &str,
    verdict: VerdictValueArg,
    reason: Option<&str>,
    keep_prepared_inputs: bool,
    json_output: bool,
) -> u8 {
    match run_verdict_set_inner(
        repo,
        pr_number,
        sha,
        dimension,
        verdict,
        reason,
        keep_prepared_inputs,
        json_output,
    ) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_verdict_set_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn run_verdict_set_inner(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    dimension: &str,
    verdict: VerdictValueArg,
    reason: Option<&str>,
    keep_prepared_inputs: bool,
    json_output: bool,
) -> Result<u8, String> {
    let projected = verdict_projection::persist_verdict_projection(
        repo,
        pr_number,
        sha,
        dimension,
        verdict.as_str(),
        reason,
        json_output,
    )?;
    if !keep_prepared_inputs {
        if let Err(err) = super::prepare::cleanup_prepared_review_inputs(
            &projected.owner_repo,
            projected.pr_number,
            &projected.head_sha,
        ) {
            eprintln!("WARNING: failed to clean prepared review inputs: {err}");
        }
    }

    let termination_state =
        state::load_review_run_state_strict(projected.pr_number, &projected.review_state_type)?;
    let termination_state_non_terminal_alive = termination_state
        .as_ref()
        .is_some_and(|state| state.status == super::types::ReviewRunStatus::Alive);
    let run_id = termination_state
        .as_ref()
        .map(|state| state.run_id.clone())
        .unwrap_or_default();
    let authority = TerminationAuthority::new(
        &projected.owner_repo,
        projected.pr_number,
        &projected.review_state_type,
        &projected.head_sha,
        &run_id,
        projected.decision_comment_id,
        &projected.decision_author,
        &now_iso8601(),
        &projected.decision_signature,
    );
    let home = apm2_home_dir()?;
    let projected_decision = projected.decision.clone();
    let caller_pid = current_process_id();
    let called_by_review_agent = termination_state
        .as_ref()
        .and_then(|state| state.pid)
        .is_some_and(|reviewer_pid| is_descendant_of_pid(caller_pid, reviewer_pid));
    let finalize_verdict = || -> Result<u8, String> {
        let lifecycle_dimension = match projected.review_state_type.as_str() {
            "quality" => "code-quality".to_string(),
            "security" => "security".to_string(),
            _ => normalize_verdict_dimension(dimension)?.to_string(),
        };
        apply_event(
            &projected.owner_repo,
            projected.pr_number,
            &projected.head_sha,
            &LifecycleEventKind::VerdictSet {
                dimension: lifecycle_dimension,
                decision: projected_decision.clone(),
            },
        )?;
        dispatch::write_completion_receipt_for_verdict(&home, &authority, &projected_decision)?;
        Ok(exit_codes::SUCCESS)
    };

    if called_by_review_agent {
        let review_type = projected.review_state_type.as_str();
        if !run_id.is_empty() {
            if let Some(agent_type) = reviewer_agent_type(review_type) {
                if let Err(err) = mark_registered_agent_reaped(
                    &projected.owner_repo,
                    projected.pr_number,
                    &run_id,
                    agent_type,
                    "verdict_set_by_child_of_reviewer",
                ) {
                    eprintln!(
                        "WARNING: failed to reclaim registry slot for PR #{} run_id={run_id}: {err}",
                        projected.pr_number
                    );
                }
            } else {
                eprintln!(
                    "WARNING: unknown review type `{review_type}` while reclaiming registry for verdict set"
                );
            }
        }
        return finalize_verdict();
    }

    match dispatch::terminate_review_agent_for_home(&home, &authority)? {
        dispatch::TerminationOutcome::Killed | dispatch::TerminationOutcome::AlreadyDead => {
            finalize_verdict()
        },
        dispatch::TerminationOutcome::SkippedMismatch => {
            if termination_state_non_terminal_alive {
                return Err(format!(
                    "verdict NOT finalized for PR #{} type={}: termination authority mismatch while lane was alive",
                    projected.pr_number, dimension
                ));
            }
            finalize_verdict()
        },
        dispatch::TerminationOutcome::IdentityFailure(reason) => Err(format!(
            "verdict NOT finalized for PR #{} type={}: reviewer termination failed (identity): {reason}",
            projected.pr_number, dimension
        )),
    }
}

pub fn run_verdict_show(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    json_output: bool,
) -> u8 {
    match verdict_projection::run_verdict_show(repo, pr_number, sha, json_output) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_verdict_show_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_recover(
    repo: &str,
    pr_number: Option<u32>,
    force: bool,
    refresh_identity: bool,
    json_output: bool,
) -> u8 {
    match run_recover_inner(repo, pr_number, force, refresh_identity) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Recover");
                println!("  Repo:              {}", summary.owner_repo);
                println!("  PR:                #{}", summary.pr_number);
                println!("  Head SHA:          {}", summary.head_sha);
                println!("  Reaped Agents:     {}", summary.reaped_agents);
                println!("  Refreshed Identity:{}", summary.refreshed_identity);
                println!("  Lifecycle State:   {}", summary.state);
            }
            exit_codes::SUCCESS
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_recover_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_recover_inner(
    repo: &str,
    pr_number: Option<u32>,
    force: bool,
    refresh_identity: bool,
) -> Result<RecoverSummary, String> {
    ensure_machine_artifact()?;
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let head_sha = fetch_pr_head_sha_authoritative(&owner_repo, resolved_pr)?;
    validate_expected_head_sha(&head_sha)?;

    let _lock = acquire_registry_lock()?;
    let mut registry = load_registry()?;
    let reaped = reap_registry_stale_entries(&mut registry);
    save_registry(&registry)?;

    let mut reduced = load_pr_state_for_recover(&owner_repo, resolved_pr, &head_sha, force)?;
    apply_event_to_record(
        &mut reduced,
        &head_sha,
        &LifecycleEventKind::RecoverRequested,
    )?;
    save_pr_state(&reduced)?;
    apply_event_to_record(
        &mut reduced,
        &head_sha,
        &LifecycleEventKind::RecoverCompleted,
    )?;
    save_pr_state(&reduced)?;

    if refresh_identity {
        projection_store::save_identity_with_context(
            &owner_repo,
            resolved_pr,
            &head_sha,
            "recover",
        )
        .map_err(|err| format!("failed to refresh local projection identity: {err}"))?;
    }

    Ok(RecoverSummary {
        schema: RECOVER_SUMMARY_SCHEMA.to_string(),
        owner_repo,
        pr_number: resolved_pr,
        refreshed_identity: refresh_identity,
        head_sha: head_sha.to_ascii_lowercase(),
        reaped_agents: reaped,
        state: reduced.pr_state.as_str().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{
        AgentType, LifecycleEventKind, PrLifecycleState, TrackedAgentState, active_agents_for_pr,
        apply_event, load_registry, register_agent_spawn, register_reviewer_dispatch, token_hash,
    };
    use crate::commands::fac_review::lifecycle::tracked_agent_id;

    static UNIQUE_PR_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn next_pr() -> u32 {
        let seq = UNIQUE_PR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let entropy = now.subsec_nanos() ^ seq.rotate_left(13) ^ std::process::id();
        1_000_000 + (entropy % 3_000_000_000)
    }

    fn next_repo(tag: &str, pr: u32) -> String {
        format!("example/{tag}-{pr}")
    }

    #[test]
    fn reducer_transitions_to_merge_ready_after_dual_approve() {
        let pr = next_pr();
        let repo = next_repo("reducer", pr);
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates start");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("gates pass");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::ReviewsDispatched).expect("dispatch");
        let _ = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "security".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("security approve");
        let state = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "code-quality".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("quality approve");
        assert_eq!(state.pr_state, PrLifecycleState::MergeReady);
    }

    #[test]
    fn reducer_remains_verdict_deny_after_other_dimension_approves() {
        let pr = next_pr();
        let repo = next_repo("deny-sticky", pr);
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates start");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("gates pass");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::ReviewsDispatched).expect("dispatch");
        let denied = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "security".to_string(),
                decision: "deny".to_string(),
            },
        )
        .expect("security deny");
        assert_eq!(denied.pr_state, PrLifecycleState::VerdictDeny);

        let still_denied = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "code-quality".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("quality approve");
        assert_eq!(still_denied.pr_state, PrLifecycleState::VerdictDeny);
    }

    #[test]
    fn recover_requested_is_rejected_from_non_recovery_states() {
        let pr = next_pr();
        let repo = next_repo("recover-guard", pr);
        let sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let err = apply_event(&repo, pr, sha, &LifecycleEventKind::RecoverRequested)
            .expect_err("recover_requested should be illegal from untracked");
        assert!(err.contains("illegal transition"));
    }

    #[test]
    fn recover_completed_requires_recovering_state() {
        let pr = next_pr();
        let repo = next_repo("recover-complete-guard", pr);
        let sha = "cccccccccccccccccccccccccccccccccccccccc";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let err = apply_event(&repo, pr, sha, &LifecycleEventKind::RecoverCompleted)
            .expect_err("recover_completed should require recovering");
        assert!(err.contains("illegal transition"));
    }

    #[test]
    fn at_capacity_is_enforced_for_same_pr() {
        let pr = next_pr();
        let repo = next_repo("capacity", pr);
        let sha = "2222222222222222222222222222222222222222";
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-security-s1-22222222"),
            AgentType::ReviewerSecurity,
            None,
            None,
        )
        .expect("first");
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-quality-s2-22222222"),
            AgentType::ReviewerQuality,
            None,
            None,
        )
        .expect("second");
        let err = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-impl-s3-22222222"),
            AgentType::Implementer,
            None,
            None,
        )
        .expect_err("third should fail");
        assert!(err.contains("at_capacity"));
    }

    #[test]
    fn helper_functions_are_stable() {
        let id = tracked_agent_id("owner/repo", 99, "run-1", AgentType::Implementer);
        assert!(id.contains("owner/repo"));
        assert!(id.contains("run-1"));
        let hash = token_hash("token");
        assert_eq!(hash.len(), 64);
        let registry = load_registry().expect("registry");
        let _ = active_agents_for_pr(&registry, "owner/repo", 99);
    }

    #[test]
    fn register_reviewer_dispatch_rolls_back_registry_on_illegal_lifecycle_transition() {
        let pr = next_pr();
        let repo = next_repo("dispatch-rollback", pr);
        let sha = "dddddddddddddddddddddddddddddddddddddddd";
        let run_id = format!("pr{pr}-security-s1-dddddddd");

        let err = register_reviewer_dispatch(&repo, pr, sha, "security", Some(&run_id), None, None)
            .expect_err(
                "register should fail because lifecycle transition is illegal from untracked",
            );
        assert!(err.contains("illegal transition"));

        let registry = load_registry().expect("registry");
        assert_eq!(active_agents_for_pr(&registry, &repo, pr), 0);
        let entry_id = tracked_agent_id(&repo, pr, &run_id, AgentType::ReviewerSecurity);
        let entry = registry
            .entries
            .iter()
            .find(|value| value.agent_id == entry_id)
            .expect("spawned registry entry should exist for forensic audit");
        assert_eq!(entry.state, TrackedAgentState::Reaped);
        assert_eq!(
            entry.reap_reason.as_deref(),
            Some("rollback:lifecycle_reviews_dispatched_failed")
        );
    }
}
