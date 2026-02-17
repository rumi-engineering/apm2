//! Reducer-first FAC lifecycle authority.
//!
//! This module defines a machine-readable lifecycle model and a single
//! reducer entrypoint for PR/SHA lifecycle transitions and agent lifecycle
//! bookkeeping.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, id as current_process_id};

use apm2_core::fac::{
    MergeReceipt, parse_b3_256_digest, parse_policy_hash, persist_signed_envelope, sign_receipt,
};
use chrono::{DateTime, Duration, Utc};
use clap::ValueEnum;
use fs2::FileExt;
use hmac::{Hmac, Mac};
use prost::Message;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_jcs;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::types::{
    DISPATCH_PENDING_TTL, TerminationAuthority, apm2_home_dir, ensure_parent_dir,
    normalize_decision_dimension as normalize_verdict_dimension, now_iso8601, sanitize_for_path,
    validate_expected_head_sha,
};
use super::{
    dispatch, findings_store, github_projection, projection_store, state, verdict_projection,
};
use crate::exit_codes::codes as exit_codes;

const MACHINE_SCHEMA: &str = "apm2.fac.lifecycle_machine.v1";
const PR_STATE_SCHEMA: &str = "apm2.fac.lifecycle_state.v1";
const AGENT_REGISTRY_SCHEMA: &str = "apm2.fac.agent_registry.v1";
const MAX_EVENT_HISTORY: usize = 256;
const MAX_ACTIVE_AGENTS_PER_PR: usize = 2;
const MAX_REGISTRY_ENTRIES: usize = 4096;
const MAX_ERROR_BUDGET: u32 = 10;
const DEFAULT_RETRY_BUDGET: u32 = 3;
const REGISTRY_NON_ACTIVE_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const DEFAULT_TOKEN_TTL_SECS: i64 = 3600;
const NO_PID_ACTIVE_TTL_MULTIPLIER: u64 = 2;
const PR_STATE_INTEGRITY_ROLE: &str = "pr_state";
const REGISTRY_INTEGRITY_ROLE: &str = "agent_registry";
const RUN_SECRET_MAX_FILE_BYTES: u64 = 128;
const RUN_SECRET_LEN_BYTES: usize = 32;
const RUN_SECRET_MAX_ENCODED_CHARS: usize = 128;
const LIFECYCLE_HMAC_ERROR: &str = "lifecycle state integrity check failed";
const FAC_STATUS_DESCRIPTION_PENDING: &str = "Forge Admission Cycle pending reviewer verdicts";
const FAC_STATUS_DESCRIPTION_SUCCESS: &str = "Forge Admission Cycle approved";
const FAC_STATUS_DESCRIPTION_DENIED: &str = "Forge Admission Cycle denied";
const FAC_STATUS_DESCRIPTION_FAIL_CLOSED: &str = "Forge Admission Cycle integrity failure";
const FAC_STATUS_PROJECTION_MAX_ATTEMPTS: usize = 3;
const FAC_RECEIPTS_DIR: &str = "receipts";
const MERGE_EVIDENCE_SCHEMA: &str = "apm2.fac.merge_evidence_projection.v1";
const MERGE_EVIDENCE_START: &str = "<!-- apm2-merge-evidence:start -->";
const MERGE_EVIDENCE_END: &str = "<!-- apm2-merge-evidence:end -->";
const MERGE_RECEIPT_PROTO_SUFFIX: &str = ".merge_receipt.pb";
const MERGE_RECEIPT_BINDING_SUFFIX: &str = ".merge_binding.json";
const MERGE_RECEIPT_CONTENT_HASH_PREFIX: &[u8] = b"apm2.fac.merge_receipt.content_hash.v1\0";
const SHA256_HEX_LEN: usize = 64;
const MERGE_PROJECTION_REPLAY_SCAN_LIMIT: usize = 64;
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
    Merged,
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
            Self::Merged => "merged",
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
pub(super) struct BypassReapOutcome {
    pub before_active_agents: usize,
    pub after_active_agents: usize,
    pub reaped_agents: usize,
    pub auto_verdict_applied: usize,
    pub auto_verdict_pending: usize,
    pub auto_verdict_skipped_existing: usize,
    pub auto_verdict_failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct BypassLifecycleResetOutcome {
    pub before_state: String,
    pub after_state: String,
    pub previous_event_seq: u64,
    pub current_event_seq: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct BypassRegistryRepairOutcome {
    pub before_active_agents: usize,
    pub after_active_agents: usize,
    pub before_total_entries: usize,
    pub after_total_entries: usize,
    pub reaped_agents: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantined_registry_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct AutoVerdictCandidate {
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    review_type: String,
    run_id: String,
}

#[derive(Debug, Default, Clone)]
struct ReapRegistryResult {
    reaped: usize,
    auto_verdict_candidates: Vec<AutoVerdictCandidate>,
}

#[derive(Debug, Default, Clone, Copy)]
struct AutoVerdictOutcome {
    applied: usize,
    pending: usize,
    skipped_existing: usize,
    failed: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum LifecycleEventKind {
    PushObserved,
    GatesStarted,
    GatesPassed,
    GatesFailed,
    ReviewsDispatched,
    ReviewerSpawned {
        review_type: String,
    },
    VerdictSet {
        dimension: String,
        decision: String,
    },
    VerdictAutoDerived {
        dimension: String,
        decision: String,
        source: String,
    },
    MergeFailed {
        reason: String,
    },
    Merged {
        source: String,
    },
    AgentCrashed {
        agent_type: AgentType,
    },
    ShaDriftDetected,
    RecoverRequested,
    RecoverCompleted,
    Quarantined {
        reason: String,
    },
    ProjectionFailed {
        reason: String,
    },
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
            Self::VerdictAutoDerived { .. } => "verdict_auto_derived",
            Self::MergeFailed { .. } => "merge_failed",
            Self::Merged { .. } => "merged",
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
        return Err(format!(
            "missing lifecycle integrity_hmac for {} PR #{}",
            state.owner_repo, state.pr_number
        ));
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
        return Err("missing agent registry integrity_hmac".to_string());
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

fn registry_quarantine_path() -> Result<PathBuf, String> {
    let path = registry_path()?;
    let state_parent = path
        .parent()
        .ok_or_else(|| format!("agent registry path has no parent: {}", path.display()))?
        .join(".quarantine");
    ensure_parent_dir(&state_parent.join("registry.quarantine"))?;
    let stamp = Utc::now().timestamp_millis();
    for attempt in 0..64 {
        let candidate =
            state_parent.join(format!("agent_registry.{stamp}.{attempt}.json.quarantine"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "failed to allocate agent registry quarantine path under {}",
        state_parent.display()
    ))
}

fn quarantine_registry() -> Result<Option<PathBuf>, String> {
    let path = registry_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let quarantine = registry_quarantine_path()?;
    fs::rename(&path, &quarantine).map_err(|err| {
        format!(
            "failed to quarantine agent registry {} -> {}: {err}",
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
    let stale = prune_registry_stale_non_active_entries(registry);
    let excess = prune_registry_to_entry_limit(registry);
    if stale + excess > 0 {
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

fn load_pr_state_bypass_hmac(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    force: bool,
) -> Result<PrLifecycleRecord, String> {
    if force {
        let _ = quarantine_pr_state(owner_repo, pr_number);
        return new_pr_state(owner_repo, pr_number, sha);
    }

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

    let Ok(mut parsed) = serde_json::from_slice::<PrLifecycleRecord>(&bytes) else {
        let _ = quarantine_pr_state(owner_repo, pr_number);
        return new_pr_state(owner_repo, pr_number, sha);
    };

    if parsed.schema != PR_STATE_SCHEMA {
        let _ = quarantine_pr_state(owner_repo, pr_number);
        return new_pr_state(owner_repo, pr_number, sha);
    }

    parsed.owner_repo = owner_repo.to_ascii_lowercase();
    parsed.pr_number = pr_number;
    if validate_expected_head_sha(&parsed.current_sha).is_err() {
        parsed.current_sha = sha.to_ascii_lowercase();
    } else {
        parsed.current_sha = parsed.current_sha.to_ascii_lowercase();
    }
    Ok(parsed)
}

fn save_pr_state(state: &PrLifecycleRecord) -> Result<PathBuf, String> {
    let mut record = state.clone();
    record.integrity_hmac = None;
    bind_pr_lifecycle_record_integrity(&mut record)?;
    let path = pr_state_path(&record.owner_repo, record.pr_number)?;
    atomic_write_json(&path, &record)?;
    Ok(path)
}

fn save_pr_state_bypass_hmac(state: &PrLifecycleRecord) -> Result<PathBuf, String> {
    save_pr_state(state)
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

fn load_registry_bypass_hmac(force: bool) -> Result<AgentRegistry, String> {
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
    let mut parsed = match serde_json::from_slice::<AgentRegistry>(&bytes) {
        Ok(value) => value,
        Err(err) => {
            if force {
                let _ = quarantine_registry();
                return Ok(AgentRegistry::default());
            }
            return Err(format!(
                "failed to parse agent registry {}: {err}",
                path.display()
            ));
        },
    };
    if parsed.schema != AGENT_REGISTRY_SCHEMA {
        if force {
            let _ = quarantine_registry();
            return Ok(AgentRegistry::default());
        }
        return Err(format!(
            "unexpected agent registry schema {} at {}",
            parsed.schema,
            path.display()
        ));
    }
    apply_registry_retention(&mut parsed);
    parsed.updated_at = now_iso8601();
    Ok(parsed)
}

fn save_registry_bypass_hmac(registry: &AgentRegistry) -> Result<PathBuf, String> {
    save_registry(registry)
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
        LifecycleEventKind::ReviewsDispatched => {
            record.verdicts.clear();
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

fn no_pid_active_ttl() -> Duration {
    let secs = DISPATCH_PENDING_TTL
        .as_secs()
        .saturating_mul(NO_PID_ACTIVE_TTL_MULTIPLIER);
    let capped = i64::try_from(secs).unwrap_or(i64::MAX);
    Duration::seconds(capped)
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
    let mut active_ids = BTreeSet::new();
    registry
        .entries
        .iter()
        .filter(|entry| entry.owner_repo.eq_ignore_ascii_case(&owner_repo))
        .filter(|entry| entry.pr_number == pr_number)
        .filter(|entry| entry.state.is_active())
        .filter(|entry| active_ids.insert(entry.agent_id.clone()))
        .count()
}

const fn review_type_for_agent_type(agent_type: AgentType) -> Option<&'static str> {
    match agent_type {
        AgentType::ReviewerSecurity => Some("security"),
        AgentType::ReviewerQuality => Some("quality"),
        _ => None,
    }
}

enum NoPidReconcileOutcome {
    Hydrated,
    Defer(&'static str),
    Reap(&'static str),
}

enum NoPidAgeStatus {
    NotExpired,
    Expired,
    InvalidStartedAt,
}

fn no_pid_age_status(entry: &TrackedAgent, stale_without_pid_after: Duration) -> NoPidAgeStatus {
    let Some(started_at) = parse_utc(&entry.started_at) else {
        return NoPidAgeStatus::InvalidStartedAt;
    };
    let Ok(elapsed) = Utc::now().signed_duration_since(started_at).to_std() else {
        return NoPidAgeStatus::NotExpired;
    };
    if elapsed >= stale_without_pid_after.to_std().unwrap_or_default() {
        NoPidAgeStatus::Expired
    } else {
        NoPidAgeStatus::NotExpired
    }
}

fn reconcile_active_entry_with_run_state(entry: &mut TrackedAgent) -> NoPidReconcileOutcome {
    let Some(review_type) = review_type_for_agent_type(entry.agent_type) else {
        return NoPidReconcileOutcome::Defer("unsupported_agent_type");
    };
    let run_state = match state::load_review_run_state(entry.pr_number, review_type) {
        Ok(state::ReviewRunStateLoad::Present(value)) => value,
        Ok(state::ReviewRunStateLoad::Missing { .. }) => {
            return NoPidReconcileOutcome::Defer("run_state_missing");
        },
        Ok(state::ReviewRunStateLoad::Corrupt { .. }) => {
            return NoPidReconcileOutcome::Defer("run_state_corrupt");
        },
        Ok(state::ReviewRunStateLoad::Ambiguous { .. }) => {
            return NoPidReconcileOutcome::Defer("run_state_ambiguous");
        },
        Err(_) => return NoPidReconcileOutcome::Defer("run_state_unavailable"),
    };

    if !run_state.owner_repo.eq_ignore_ascii_case(&entry.owner_repo) {
        return NoPidReconcileOutcome::Reap("run_state_repo_mismatch");
    }
    if !run_state.head_sha.eq_ignore_ascii_case(&entry.sha) {
        return NoPidReconcileOutcome::Reap("run_state_sha_mismatch");
    }
    if run_state.run_id != entry.run_id {
        return NoPidReconcileOutcome::Reap("run_state_run_id_mismatch");
    }
    if run_state.status.is_terminal() {
        return NoPidReconcileOutcome::Reap("run_state_terminal");
    }

    let Some(pid) = run_state.pid else {
        return NoPidReconcileOutcome::Defer("run_state_pid_missing");
    };
    if !state::is_process_alive(pid) {
        return NoPidReconcileOutcome::Reap("run_state_pid_not_alive");
    }
    if let Some(expected_start) = run_state.proc_start_time {
        let observed = state::get_process_start_time(pid);
        if observed.is_some_and(|value| value != expected_start) {
            return NoPidReconcileOutcome::Reap("run_state_pid_reused");
        }
    }

    entry.pid = Some(pid);
    entry.proc_start_time = run_state.proc_start_time;
    entry.state = TrackedAgentState::Running;
    NoPidReconcileOutcome::Hydrated
}

fn reap_registry_stale_entries(registry: &mut AgentRegistry) -> ReapRegistryResult {
    reap_registry_stale_entries_scoped(registry, None)
}

fn reap_registry_stale_entries_scoped(
    registry: &mut AgentRegistry,
    scope: Option<(&str, u32)>,
) -> ReapRegistryResult {
    let mut result = ReapRegistryResult::default();
    let stale_without_pid_after = no_pid_active_ttl();
    let normalized_scope = scope.map(|(repo, pr_number)| (repo.to_ascii_lowercase(), pr_number));
    for entry in &mut registry.entries {
        if let Some((scope_repo, scope_pr_number)) = &normalized_scope
            && (!entry.owner_repo.eq_ignore_ascii_case(scope_repo)
                || entry.pr_number != *scope_pr_number)
        {
            continue;
        }
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
            let mut deferred_reap_reason = None;
            if matches!(
                entry.agent_type,
                AgentType::ReviewerSecurity | AgentType::ReviewerQuality
            ) {
                match reconcile_active_entry_with_run_state(entry) {
                    NoPidReconcileOutcome::Hydrated => {},
                    NoPidReconcileOutcome::Defer(reason) => {
                        deferred_reap_reason = Some(reason);
                    },
                    NoPidReconcileOutcome::Reap(reason) => {
                        reap_reason = Some(reason);
                    },
                }
            }
            if entry.pid.is_some() {
                continue;
            }
            if reap_reason.is_none() {
                match no_pid_age_status(entry, stale_without_pid_after) {
                    NoPidAgeStatus::NotExpired => {},
                    NoPidAgeStatus::Expired => {
                        reap_reason = Some(deferred_reap_reason.unwrap_or("stale_without_pid"));
                    },
                    NoPidAgeStatus::InvalidStartedAt => {
                        reap_reason = Some(
                            deferred_reap_reason.unwrap_or("stale_without_pid_invalid_started_at"),
                        );
                    },
                }
            }
        }

        if let Some(reason) = reap_reason {
            entry.state = TrackedAgentState::Reaped;
            entry.completed_at = Some(now_iso8601());
            entry.reap_reason = Some(reason.to_string());
            result.reaped = result.reaped.saturating_add(1);
            if let Some(review_type) = review_type_for_agent_type(entry.agent_type) {
                result.auto_verdict_candidates.push(AutoVerdictCandidate {
                    owner_repo: entry.owner_repo.clone(),
                    pr_number: entry.pr_number,
                    head_sha: entry.sha.clone(),
                    review_type: review_type.to_string(),
                    run_id: entry.run_id.clone(),
                });
            }
        }
    }
    if result.reaped > 0 {
        registry.updated_at = now_iso8601();
    }
    result
}

enum AutoVerdictFinalizeResult {
    Applied,
    Pending,
    SkippedExisting,
}

fn candidate_matches_current_pr_head(candidate: &AutoVerdictCandidate) -> Result<bool, String> {
    let Some(snapshot) = load_pr_lifecycle_snapshot(&candidate.owner_repo, candidate.pr_number)?
    else {
        return Ok(true);
    };
    Ok(snapshot
        .current_sha
        .eq_ignore_ascii_case(&candidate.head_sha))
}

fn derive_auto_verdict_decision_from_findings(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
) -> Result<Option<&'static str>, String> {
    let Some(bundle) = findings_store::load_findings_bundle(owner_repo, pr_number, head_sha)?
    else {
        return Ok(None);
    };
    let Some(dimension_findings) = findings_store::find_dimension(&bundle, dimension) else {
        return Ok(None);
    };
    if dimension_findings.findings.is_empty() {
        return Ok(None);
    }

    let mut saw_major_or_blocker = false;
    for finding in &dimension_findings.findings {
        match finding.severity.trim().to_ascii_uppercase().as_str() {
            "MINOR" | "NIT" => {},
            // Fail closed for unknown severities.
            _ => {
                saw_major_or_blocker = true;
                break;
            },
        }
    }

    if saw_major_or_blocker {
        Ok(Some("deny"))
    } else {
        Ok(Some("approve"))
    }
}

fn resolve_lifecycle_dimension(
    projected_review_type: &str,
    fallback_dimension: &str,
) -> Result<String, String> {
    match projected_review_type {
        "quality" => Ok("code-quality".to_string()),
        "security" => Ok("security".to_string()),
        _ => Ok(normalize_verdict_dimension(fallback_dimension)?.to_string()),
    }
}

fn git_run_checked(current_dir: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(current_dir)
        .output()
        .map_err(|err| format!("failed to execute `git {}`: {err}", args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(format!(
        "`git {}` failed: {}",
        args.join(" "),
        if stderr.is_empty() {
            "unknown error"
        } else {
            &stderr
        }
    ))
}

fn git_stdout_checked(current_dir: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(current_dir)
        .output()
        .map_err(|err| format!("failed to execute `git {}`: {err}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "`git {}` failed: {}",
            args.join(" "),
            if stderr.is_empty() {
                "unknown error"
            } else {
                &stderr
            }
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_commit_sha_if_exists(current_dir: &Path, reference: &str) -> Result<Option<String>, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", reference])
        .current_dir(current_dir)
        .output()
        .map_err(|err| {
            format!(
                "failed to resolve `{reference}` in {}: {err}",
                current_dir.display()
            )
        })?;
    match output.status.code() {
        Some(0) => Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        )),
        Some(1) => Ok(None),
        Some(_) | None => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(format!(
                "failed to resolve `{reference}` in {}: {}",
                current_dir.display(),
                if stderr.is_empty() {
                    "unknown error"
                } else {
                    &stderr
                }
            ))
        },
    }
}

fn git_update_ref_if_missing(
    current_dir: &Path,
    reference: &str,
    new_sha: &str,
) -> Result<bool, String> {
    validate_expected_head_sha(new_sha)?;
    let output = Command::new("git")
        .args([
            "update-ref",
            reference,
            new_sha,
            "0000000000000000000000000000000000000000",
        ])
        .current_dir(current_dir)
        .output()
        .map_err(|err| {
            format!(
                "failed to create `{reference}` in {}: {err}",
                current_dir.display()
            )
        })?;
    if output.status.success() {
        return Ok(true);
    }

    let verify_ref = format!("{reference}^{{commit}}");
    if git_commit_sha_if_exists(current_dir, &verify_ref)?.is_some() {
        return Ok(false);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(format!(
        "failed to create `{reference}` in {}: {}",
        current_dir.display(),
        if stderr.is_empty() {
            "unknown error"
        } else {
            &stderr
        }
    ))
}

fn git_worktree_has_tracked_changes(current_dir: &Path) -> Result<bool, String> {
    let output = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .current_dir(current_dir)
        .output()
        .map_err(|err| format!("failed to inspect git worktree cleanliness: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "failed to inspect git worktree cleanliness: {}",
            if stderr.is_empty() {
                "unknown error"
            } else {
                &stderr
            }
        ));
    }
    Ok(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn find_main_worktree(reference_dir: &Path) -> Result<Option<PathBuf>, String> {
    let listing = git_stdout_checked(reference_dir, &["worktree", "list", "--porcelain"])?;
    if listing.trim().is_empty() {
        let active_branch =
            git_stdout_checked(reference_dir, &["rev-parse", "--abbrev-ref", "HEAD"])?;
        if active_branch == "main" {
            return Ok(Some(reference_dir.to_path_buf()));
        }
        return Ok(None);
    }

    let mut current_path: Option<PathBuf> = None;
    let mut current_branch: Option<String> = None;
    let mut main_candidate: Option<PathBuf> = None;
    for line in listing.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            if let (Some(path), Some(branch)) = (current_path.take(), current_branch.take())
                && branch == "refs/heads/main"
            {
                main_candidate = Some(path);
            }
            current_path = Some(PathBuf::from(path));
            continue;
        }
        if let Some(branch) = line.strip_prefix("branch ") {
            current_branch = Some(branch.to_string());
        }
    }
    if let (Some(path), Some(branch)) = (current_path.take(), current_branch.take())
        && branch == "refs/heads/main"
    {
        main_candidate = Some(path);
    }
    if let Some(path) = main_candidate {
        return Ok(Some(path));
    }

    let active_branch = git_stdout_checked(reference_dir, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    if active_branch == "main" {
        return Ok(Some(reference_dir.to_path_buf()));
    }
    Ok(None)
}

fn git_merge_base_is_ancestor(
    current_dir: &Path,
    ancestor_ref: &str,
    descendant_ref: &str,
) -> Result<bool, String> {
    let output = Command::new("git")
        .args(["merge-base", "--is-ancestor", ancestor_ref, descendant_ref])
        .current_dir(current_dir)
        .output()
        .map_err(|err| format!("failed to execute git merge-base: {err}"))?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        Some(_) | None => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(format!(
                "failed to validate ancestor relation {} -> {}: {}",
                ancestor_ref,
                descendant_ref,
                if stderr.is_empty() {
                    "unknown error"
                } else {
                    &stderr
                }
            ))
        },
    }
}

fn sync_main_worktree_if_present(reference_dir: &Path) {
    let Ok(Some(main_worktree)) = find_main_worktree(reference_dir) else {
        return;
    };
    match git_worktree_has_tracked_changes(&main_worktree) {
        Ok(true) => {
            eprintln!(
                "WARNING: skipped syncing main worktree {} because it has local tracked changes",
                main_worktree.display()
            );
            return;
        },
        Ok(false) => {},
        Err(err) => {
            eprintln!(
                "WARNING: failed to inspect main worktree cleanliness at {}: {err}",
                main_worktree.display()
            );
            return;
        },
    }
    if let Err(err) = git_run_checked(&main_worktree, &["reset", "--hard", "HEAD"]) {
        eprintln!(
            "WARNING: failed to sync main worktree {} after ref update: {err}",
            main_worktree.display()
        );
        return;
    }
    if let Err(err) = git_run_checked(&main_worktree, &["clean", "-fd"]) {
        eprintln!(
            "WARNING: failed to clean untracked files in main worktree {} after ref update: {err}",
            main_worktree.display()
        );
    }
}

fn sync_local_main_with_origin(current_dir: &Path) -> Result<(), String> {
    git_run_checked(
        current_dir,
        &[
            "fetch",
            "origin",
            "refs/heads/main:refs/remotes/origin/main",
        ],
    )?;
    let remote_main = git_commit_sha_if_exists(current_dir, "refs/remotes/origin/main^{commit}")?
        .ok_or_else(|| "origin/main not found after fetch".to_string())?;
    validate_expected_head_sha(&remote_main)?;
    let mut local_main = git_commit_sha_if_exists(current_dir, "refs/heads/main^{commit}")?;

    if local_main.is_none() {
        if git_update_ref_if_missing(current_dir, "refs/heads/main", &remote_main)? {
            sync_main_worktree_if_present(current_dir);
            return Ok(());
        }
        local_main = git_commit_sha_if_exists(current_dir, "refs/heads/main^{commit}")?;
    }

    let Some(local_main) = local_main else {
        return Err("refs/heads/main is missing after attempted sync from origin/main".to_string());
    };
    validate_expected_head_sha(&local_main)?;

    if local_main.eq_ignore_ascii_case(&remote_main) {
        return Ok(());
    }

    if git_merge_base_is_ancestor(current_dir, "refs/remotes/origin/main", "refs/heads/main")? {
        return Ok(());
    }

    if git_merge_base_is_ancestor(current_dir, "refs/heads/main", "refs/remotes/origin/main")? {
        return Err(
            "origin/main is ahead of local main; refusing remote-authoritative main sync"
                .to_string(),
        );
    }

    Err("local main diverged from origin/main; manual rebase/repair required".to_string())
}

fn push_local_main_to_origin(current_dir: &Path, expected_main_sha: &str) -> Result<(), String> {
    validate_expected_head_sha(expected_main_sha)?;
    let local_main = git_stdout_checked(
        current_dir,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "refs/heads/main^{commit}",
        ],
    )?;
    if !local_main.eq_ignore_ascii_case(expected_main_sha) {
        return Err(format!(
            "auto-merge push aborted: local main {local_main} no longer matches expected merged SHA {expected_main_sha}"
        ));
    }
    let push_refspec = format!("{expected_main_sha}:refs/heads/main");
    git_run_checked(current_dir, &["push", "origin", &push_refspec])
}

fn try_fast_forward_main(
    current_dir: &Path,
    branch: &str,
    expected_sha: &str,
) -> Result<(), String> {
    let main_ref = "refs/heads/main";
    let branch_ref = format!("refs/heads/{branch}");
    let main_head = git_stdout_checked(
        current_dir,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "refs/heads/main^{commit}",
        ],
    )?;
    let branch_verify = format!("{branch_ref}^{{commit}}");
    let branch_head = git_stdout_checked(
        current_dir,
        &["rev-parse", "--verify", "--quiet", &branch_verify],
    )?;
    validate_expected_head_sha(&branch_head)?;
    if !branch_head.eq_ignore_ascii_case(expected_sha) {
        return Err(format!(
            "auto-merge refused: branch `{branch}` head {branch_head} does not match lifecycle SHA {expected_sha}"
        ));
    }

    if !git_merge_base_is_ancestor(current_dir, main_ref, &branch_ref)? {
        return Err(format!(
            "non-fast-forward merge required: main is not ancestor of `{branch}`"
        ));
    }

    git_run_checked(
        current_dir,
        &["update-ref", "refs/heads/main", &branch_head, &main_head],
    )?;
    sync_main_worktree_if_present(current_dir);
    Ok(())
}

fn maybe_cleanup_worktree_target(worktree: Option<&str>) {
    let Some(worktree) = worktree else {
        return;
    };
    let worktree_path = PathBuf::from(worktree);
    let Ok(worktree_real) = std::fs::canonicalize(&worktree_path) else {
        return;
    };
    let target = worktree_real.join("target");
    if !target.exists() {
        return;
    }
    let Ok(metadata) = std::fs::symlink_metadata(&target) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    if target.file_name().and_then(|name| name.to_str()) != Some("target") {
        return;
    }
    if target.parent() != Some(worktree_real.as_path()) {
        return;
    }
    let _ = std::fs::remove_dir_all(&target);
}

fn cleanup_merged_branch_local_state_inner(
    reference_dir: &Path,
    branch: &str,
    worktree: Option<&str>,
) -> Result<(), String> {
    let mut errors = Vec::new();
    maybe_cleanup_worktree_target(worktree);
    let mut skipped_worktree_removal_for_current_dir = false;
    if let Some(worktree_path) = worktree {
        let current_dir = std::env::current_dir().ok();
        let remove_ok = current_dir
            .as_ref()
            .is_none_or(|cwd| cwd != Path::new(worktree_path));
        if !remove_ok {
            skipped_worktree_removal_for_current_dir = true;
            errors.push(format!(
                "skipped worktree removal for `{worktree_path}` because it is the current working directory"
            ));
        } else if let Err(err) = git_run_checked(
            reference_dir,
            &["worktree", "remove", "--force", worktree_path],
        ) {
            errors.push(format!(
                "failed to remove worktree `{worktree_path}`: {err}"
            ));
        }
    }
    if !branch.eq_ignore_ascii_case("main") {
        if skipped_worktree_removal_for_current_dir {
            errors.push(format!(
                "skipped deleting local branch `{branch}` because its worktree is still active in the current directory"
            ));
        } else if let Err(err) = git_run_checked(reference_dir, &["branch", "-D", branch]) {
            errors.push(format!("failed to delete local branch `{branch}`: {err}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn cleanup_merged_branch_local_state(reference_dir: &Path, branch: &str, worktree: Option<&str>) {
    if let Err(err) = cleanup_merged_branch_local_state_inner(reference_dir, branch, worktree) {
        eprintln!("WARNING: post-merge local cleanup incomplete: {err}");
    }
}

#[derive(Debug, Clone)]
struct MergeEvidenceBinding {
    gate_job_id: String,
    gate_receipt_id: String,
    policy_hash: String,
    gate_evidence_hashes: Vec<String>,
    verdict_hashes: Vec<String>,
}

#[derive(Debug, Clone)]
struct PersistedMergeReceipt {
    content_hash: String,
    merged_at_iso: String,
}

#[derive(Debug, Clone, Serialize)]
struct MergeReceiptBindingPreimage<'a> {
    schema: &'static str,
    owner_repo: &'a str,
    pr_number: u32,
    head_sha: &'a str,
    gate_job_id: &'a str,
    gate_receipt_id: &'a str,
    gate_evidence_hashes: &'a [String],
    verdict_hashes: &'a [String],
}

#[derive(Debug, Clone, Serialize)]
struct MergeReceiptBindingRecord {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    merge_sha: String,
    merge_receipt_content_hash: String,
    gate_job_id: String,
    gate_receipt_id: String,
    policy_hash: String,
    gate_evidence_hashes: Vec<String>,
    verdict_hashes: Vec<String>,
    changeset_digest_hex: String,
    merged_at: String,
}

#[derive(Debug, Clone)]
struct MergeProjectionContext {
    owner_repo: String,
    pr_number: u32,
    merge_sha: String,
    source_branch: String,
    merge_receipt_hash: String,
    merged_at_iso: String,
    gate_job_id: String,
    gate_receipt_id: String,
    policy_hash: String,
    gate_evidence_hashes: Vec<String>,
    verdict_hashes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum MergeProjectionSink {
    Github,
}

impl MergeProjectionSink {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
        }
    }
}

fn configured_merge_projection_sinks() -> Vec<MergeProjectionSink> {
    vec![MergeProjectionSink::Github]
}

fn fac_root_dir() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("private").join("fac"))
}

fn fac_receipts_dir() -> Result<PathBuf, String> {
    Ok(fac_root_dir()?.join(FAC_RECEIPTS_DIR))
}

fn normalize_hash_list(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn normalize_sha256_hex_digest(value: &str, field: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(format!("merge receipt binding requires non-empty {field}"));
    }
    if normalized.len() != SHA256_HEX_LEN
        || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!(
            "merge receipt binding requires {field} as 64-char hex digest, found `{value}`"
        ));
    }
    Ok(normalized)
}

fn load_approved_verdict_hashes(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<Vec<String>, String> {
    let home = apm2_home_dir()?;
    let mut hashes = Vec::with_capacity(2);
    for review_type in ["security", "quality"] {
        let signal = verdict_projection::resolve_completion_signal_from_projection_for_home(
            &home,
            owner_repo,
            pr_number,
            review_type,
            head_sha,
        )?
        .ok_or_else(|| {
            format!("missing `{review_type}` completion signal for PR #{pr_number} SHA {head_sha}")
        })?;
        if signal.decision != "approve" {
            return Err(format!(
                "merge receipt binding requires approved `{review_type}` verdict, found `{}`",
                signal.decision
            ));
        }
        hashes.push(normalize_sha256_hex_digest(
            &signal.decision_summary,
            &format!("`{review_type}` decision hash"),
        )?);
    }
    let hashes = normalize_hash_list(&hashes);
    if hashes.is_empty() {
        return Err(format!(
            "merge receipt binding produced no verdict hashes for PR #{pr_number} SHA {head_sha}"
        ));
    }
    Ok(hashes)
}

fn load_merge_evidence_binding(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<MergeEvidenceBinding, String> {
    let admission = projection_store::load_gates_admission(owner_repo, pr_number, head_sha)?
        .ok_or_else(|| {
            format!(
                "missing authoritative gates admission snapshot for PR #{pr_number} SHA {head_sha}"
            )
        })?;
    let gate_job_id = admission.gate_job_id.trim().to_string();
    if gate_job_id.is_empty() {
        return Err(format!(
            "authoritative gates admission snapshot has empty gate_job_id for PR #{pr_number} SHA {head_sha}"
        ));
    }
    let gate_receipt_id = admission.gate_receipt_id.trim().to_string();
    if gate_receipt_id.is_empty() {
        return Err(format!(
            "authoritative gates admission snapshot has empty gate_receipt_id for PR #{pr_number} SHA {head_sha}"
        ));
    }
    let policy_hash = admission.policy_hash.trim().to_string();
    if policy_hash.is_empty() {
        return Err(format!(
            "authoritative gates admission snapshot has empty policy_hash for PR #{pr_number} SHA {head_sha}"
        ));
    }
    if parse_policy_hash(&policy_hash).is_none() {
        return Err(format!(
            "authoritative gates admission snapshot has invalid policy_hash `{policy_hash}` for PR #{pr_number} SHA {head_sha}"
        ));
    }
    let gate_evidence_hashes = normalize_hash_list(&admission.gate_evidence_hashes);
    if gate_evidence_hashes.is_empty() {
        return Err(format!(
            "authoritative gates admission snapshot has no gate evidence hashes for PR #{pr_number} SHA {head_sha}"
        ));
    }
    if let Some(invalid_hash) = gate_evidence_hashes
        .iter()
        .find(|value| parse_b3_256_digest(value).is_none())
    {
        return Err(format!(
            "authoritative gates admission snapshot has invalid gate evidence hash `{invalid_hash}` for PR #{pr_number} SHA {head_sha}"
        ));
    }
    let verdict_hashes = load_approved_verdict_hashes(owner_repo, pr_number, head_sha)?;
    Ok(MergeEvidenceBinding {
        gate_job_id,
        gate_receipt_id,
        policy_hash,
        gate_evidence_hashes,
        verdict_hashes,
    })
}

fn compute_merge_receipt_changeset_digest(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    binding: &MergeEvidenceBinding,
) -> Result<[u8; 32], String> {
    let preimage = MergeReceiptBindingPreimage {
        schema: MERGE_EVIDENCE_SCHEMA,
        owner_repo,
        pr_number,
        head_sha,
        gate_job_id: &binding.gate_job_id,
        gate_receipt_id: &binding.gate_receipt_id,
        gate_evidence_hashes: &binding.gate_evidence_hashes,
        verdict_hashes: &binding.verdict_hashes,
    };
    let canonical = serde_jcs::to_vec(&preimage)
        .map_err(|err| format!("failed to canonicalize merge receipt binding preimage: {err}"))?;
    let digest = blake3::hash(&canonical);
    Ok(*digest.as_bytes())
}

fn compute_merge_receipt_content_hash(proto_bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MERGE_RECEIPT_CONTENT_HASH_PREFIX);
    hasher.update(proto_bytes);
    format!("b3-256:{}", hasher.finalize().to_hex())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid output file name for {}", path.display()))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path =
        path.with_file_name(format!("{file_name}.tmp-{}-{nonce}", current_process_id()));
    fs::write(&temp_path, bytes)
        .map_err(|err| format!("failed to write temp file {}: {err}", temp_path.display()))?;
    fs::rename(&temp_path, path).map_err(|err| {
        format!(
            "failed to atomically move {} -> {}: {err}",
            temp_path.display(),
            path.display()
        )
    })
}

fn persist_merge_receipt_binding_record(
    receipts_dir: &Path,
    merge_receipt_hash: &str,
    record: &MergeReceiptBindingRecord,
) -> Result<(), String> {
    let path = receipts_dir.join(format!(
        "{merge_receipt_hash}{MERGE_RECEIPT_BINDING_SUFFIX}"
    ));
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|err| format!("failed to serialize merge receipt binding record: {err}"))?;
    write_bytes_atomic(&path, &bytes)
}

fn persist_signed_merge_receipt(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    merge_sha: &str,
    binding: &MergeEvidenceBinding,
) -> Result<PersistedMergeReceipt, String> {
    validate_expected_head_sha(head_sha)?;
    validate_expected_head_sha(merge_sha)?;
    let policy_hash = parse_policy_hash(&binding.policy_hash).ok_or_else(|| {
        format!(
            "invalid policy hash `{}` in authoritative gates admission snapshot",
            binding.policy_hash
        )
    })?;
    let changeset_digest =
        compute_merge_receipt_changeset_digest(owner_repo, pr_number, head_sha, binding)?;
    let merged_at_ns_u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0)
        .min(u128::from(u64::MAX));
    let merged_at_ns = u64::try_from(merged_at_ns_u128).unwrap_or(u64::MAX);
    let merged_at_iso = now_iso8601();
    let fac_root = fac_root_dir()?;
    let signer = crate::commands::fac_key_material::load_or_generate_persistent_signer(&fac_root)?;
    let receipt = MergeReceipt::create_after_observation(
        "main".to_string(),
        changeset_digest,
        vec![binding.gate_receipt_id.clone()],
        policy_hash,
        merge_sha.to_string(),
        merged_at_ns,
        "fac-review-cli".to_string(),
        &signer,
    )
    .map_err(|err| format!("failed to create signed merge receipt: {err}"))?;
    let receipt_proto: apm2_core::fac::MergeReceiptProto = receipt.into();
    let proto_bytes = receipt_proto.encode_to_vec();
    let content_hash = compute_merge_receipt_content_hash(&proto_bytes);

    let receipts_dir = fac_receipts_dir()?;
    let proto_path = receipts_dir.join(format!("{content_hash}{MERGE_RECEIPT_PROTO_SUFFIX}"));
    write_bytes_atomic(&proto_path, &proto_bytes)?;

    let binding_record = MergeReceiptBindingRecord {
        schema: MERGE_EVIDENCE_SCHEMA.to_string(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        head_sha: head_sha.to_string(),
        merge_sha: merge_sha.to_string(),
        merge_receipt_content_hash: content_hash.clone(),
        gate_job_id: binding.gate_job_id.clone(),
        gate_receipt_id: binding.gate_receipt_id.clone(),
        policy_hash: binding.policy_hash.clone(),
        gate_evidence_hashes: binding.gate_evidence_hashes.clone(),
        verdict_hashes: binding.verdict_hashes.clone(),
        changeset_digest_hex: hex::encode(changeset_digest),
        merged_at: merged_at_iso.clone(),
    };
    persist_merge_receipt_binding_record(&receipts_dir, &content_hash, &binding_record)?;

    let envelope = sign_receipt(&content_hash, &signer, "fac-review-cli");
    persist_signed_envelope(&receipts_dir, &envelope)
        .map_err(|err| format!("failed to persist merge receipt signed envelope: {err}"))?;

    Ok(PersistedMergeReceipt {
        content_hash,
        merged_at_iso,
    })
}

fn rollback_local_main_after_receipt_failure(
    current_dir: &Path,
    previous_main_sha: &str,
    merged_sha: &str,
) -> Result<(), String> {
    validate_expected_head_sha(previous_main_sha)?;
    validate_expected_head_sha(merged_sha)?;
    git_run_checked(
        current_dir,
        &[
            "update-ref",
            "refs/heads/main",
            previous_main_sha,
            merged_sha,
        ],
    )?;
    sync_main_worktree_if_present(current_dir);
    Ok(())
}

fn delete_remote_branch_projection(current_dir: &Path, branch: &str) -> Result<(), String> {
    let branch = branch.trim();
    if branch.is_empty() {
        return Err("cannot delete remote branch projection for empty branch name".to_string());
    }
    if branch.eq_ignore_ascii_case("main") {
        return Ok(());
    }
    let remote_ref = format!("refs/heads/{branch}");
    let remote_output = git_stdout_checked(
        current_dir,
        &["ls-remote", "--heads", "origin", &remote_ref],
    )?;
    if remote_output.trim().is_empty() {
        return Ok(());
    }
    git_run_checked(current_dir, &["push", "origin", "--delete", branch])
}

fn fetch_pr_body_for_merge_projection(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    match github_projection::fetch_pr_body(owner_repo, pr_number) {
        Ok(body) if !body.trim().is_empty() => Ok(body),
        first_result => {
            let snapshot = projection_store::load_pr_body_snapshot(owner_repo, pr_number)?;
            if let Some(body) = snapshot.as_ref()
                && !body.trim().is_empty()
            {
                return Ok(body.clone());
            }
            match first_result {
                Ok(body) => Ok(body),
                Err(err) => Err(err),
            }
        },
    }
}

fn upsert_marker_section(
    body: &str,
    start_marker: &str,
    end_marker: &str,
    section: &str,
) -> String {
    let section = section.trim_end();
    let mut output = String::new();

    if let Some(start_idx) = body.find(start_marker) {
        let search_start = start_idx + start_marker.len();
        if let Some(rel_end_idx) = body[search_start..].find(end_marker) {
            let end_idx = search_start + rel_end_idx + end_marker.len();
            let before = body[..start_idx].trim_end();
            let after = body[end_idx..].trim_start();
            if !before.is_empty() {
                output.push_str(before);
                output.push_str("\n\n");
            }
            output.push_str(section);
            if after.is_empty() {
                output.push('\n');
            } else {
                output.push_str("\n\n");
                output.push_str(after);
            }
            return output;
        }
    }

    let trimmed = body.trim_end();
    if !trimmed.is_empty() {
        output.push_str(trimmed);
        output.push_str("\n\n");
    }
    output.push_str(section);
    output.push('\n');
    output
}

fn render_merge_evidence_section(context: &MergeProjectionContext) -> String {
    let gate_evidence = if context.gate_evidence_hashes.is_empty() {
        "(none)".to_string()
    } else {
        context.gate_evidence_hashes.join(", ")
    };
    let verdict_hashes = if context.verdict_hashes.is_empty() {
        "(none)".to_string()
    } else {
        context.verdict_hashes.join(", ")
    };
    format!(
        "{MERGE_EVIDENCE_START}\n\
### FAC Merge Evidence\n\
- schema: `{MERGE_EVIDENCE_SCHEMA}`\n\
- merged_sha: `{merge_sha}`\n\
- merged_at: `{merged_at}`\n\
- merge_receipt: `{merge_receipt}`\n\
- gate_job_id: `{gate_job_id}`\n\
- gate_receipt_id: `{gate_receipt_id}`\n\
- policy_hash: `{policy_hash}`\n\
- gate_evidence_hashes: `{gate_evidence}`\n\
- verdict_hashes: `{verdict_hashes}`\n\
{MERGE_EVIDENCE_END}",
        merge_sha = context.merge_sha,
        merged_at = context.merged_at_iso,
        merge_receipt = context.merge_receipt_hash,
        gate_job_id = context.gate_job_id,
        gate_receipt_id = context.gate_receipt_id,
        policy_hash = context.policy_hash,
        gate_evidence = gate_evidence,
        verdict_hashes = verdict_hashes,
    )
}

fn project_merge_evidence_to_pr_body(context: &MergeProjectionContext) -> Result<(), String> {
    let current_body = fetch_pr_body_for_merge_projection(&context.owner_repo, context.pr_number)?;
    let section = render_merge_evidence_section(context);
    let updated_body = upsert_marker_section(
        &current_body,
        MERGE_EVIDENCE_START,
        MERGE_EVIDENCE_END,
        &section,
    );
    github_projection::edit_pr_body(&context.owner_repo, context.pr_number, &updated_body)?;
    projection_store::save_pr_body_snapshot(
        &context.owner_repo,
        context.pr_number,
        &updated_body,
        "merge_projection",
    )?;
    Ok(())
}

fn project_merge_to_github(
    merge_dir: &Path,
    context: &MergeProjectionContext,
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(err) = github_projection::close_pr_if_open(&context.owner_repo, context.pr_number) {
        errors.push(format!("close_pr: {err}"));
    }
    if let Err(err) = delete_remote_branch_projection(merge_dir, &context.source_branch) {
        errors.push(format!(
            "delete_remote_branch `{}`: {err}",
            context.source_branch
        ));
    }
    if let Err(err) = project_fac_required_status_for_decision(
        &context.owner_repo,
        context.pr_number,
        &context.merge_sha,
        "approve",
    ) {
        errors.push(format!("commit_status: {err}"));
    }
    if let Err(err) = project_merge_evidence_to_pr_body(context) {
        errors.push(format!("pr_body: {err}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn project_merge_to_all_sinks(
    merge_dir: &Path,
    context: &MergeProjectionContext,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for sink in configured_merge_projection_sinks() {
        let sink_result = match sink {
            MergeProjectionSink::Github => project_merge_to_github(merge_dir, context),
        };
        if let Err(err) = sink_result {
            errors.push(format!("{}: {err}", sink.as_str()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn save_merge_projection_pending(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    context: &MergeProjectionContext,
    reason: &str,
    attempt_count: u32,
) -> Result<(), String> {
    projection_store::save_merge_projection_pending(
        owner_repo,
        pr_number,
        head_sha,
        &projection_store::MergeProjectionPendingSaveRequest {
            merge_sha: &context.merge_sha,
            source_branch: &context.source_branch,
            merge_receipt_hash: &context.merge_receipt_hash,
            merged_at_iso: &context.merged_at_iso,
            gate_job_id: &context.gate_job_id,
            gate_receipt_id: &context.gate_receipt_id,
            policy_hash: &context.policy_hash,
            gate_evidence_hashes: &context.gate_evidence_hashes,
            verdict_hashes: &context.verdict_hashes,
            last_error: reason,
            attempt_count,
            source: "auto_merge",
        },
    )
}

fn project_merge_to_all_sinks_with_retry(
    merge_dir: &Path,
    context: &MergeProjectionContext,
    max_attempts: u32,
) -> Result<(), String> {
    let attempts = max_attempts.max(1);
    let mut last_error = String::new();
    for attempt in 1..=attempts {
        match project_merge_to_all_sinks(merge_dir, context) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_error = err;
                if attempt < attempts {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            },
        }
    }
    Err(last_error)
}

fn replay_pending_merge_projection_for_repo(owner_repo: &str) {
    let pending = match projection_store::list_merge_projection_pending_for_repo(
        owner_repo,
        MERGE_PROJECTION_REPLAY_SCAN_LIMIT,
    ) {
        Ok(value) => value,
        Err(err) => {
            eprintln!(
                "WARNING: failed to list pending merge projection records for {owner_repo}: {err}"
            );
            return;
        },
    };
    let Some(snapshot) = pending.into_iter().min_by(|lhs, rhs| {
        lhs.attempt_count
            .cmp(&rhs.attempt_count)
            .then_with(|| lhs.updated_at.cmp(&rhs.updated_at))
    }) else {
        return;
    };

    let merge_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let context = MergeProjectionContext {
        owner_repo: snapshot.owner_repo.clone(),
        pr_number: snapshot.pr_number,
        merge_sha: snapshot.merge_sha.clone(),
        source_branch: snapshot.source_branch.clone(),
        merge_receipt_hash: snapshot.merge_receipt_hash.clone(),
        merged_at_iso: snapshot.merged_at_iso.clone(),
        gate_job_id: snapshot.gate_job_id.clone(),
        gate_receipt_id: snapshot.gate_receipt_id.clone(),
        policy_hash: snapshot.policy_hash.clone(),
        gate_evidence_hashes: snapshot.gate_evidence_hashes.clone(),
        verdict_hashes: snapshot.verdict_hashes.clone(),
    };
    match project_merge_to_all_sinks_with_retry(&merge_dir, &context, 3) {
        Ok(()) => {
            if let Err(err) = projection_store::clear_merge_projection_pending(
                &snapshot.owner_repo,
                snapshot.pr_number,
                &snapshot.head_sha,
            ) {
                eprintln!(
                    "WARNING: replayed pending merge projection for PR #{} but failed to clear pending record: {err}",
                    snapshot.pr_number
                );
            }
        },
        Err(err) => {
            let next_attempt = snapshot.attempt_count.saturating_add(1);
            if let Err(persist_err) = save_merge_projection_pending(
                &snapshot.owner_repo,
                snapshot.pr_number,
                &snapshot.head_sha,
                &context,
                &err,
                next_attempt,
            ) {
                eprintln!(
                    "WARNING: failed to update pending merge projection record for PR #{} after replay failure: {persist_err}",
                    snapshot.pr_number
                );
            }
        },
    }
}

/// Run auto-merge synchronously when the PR reaches `MergeReady`. Earlier
/// versions spawned a background thread, but short-lived CLI processes
/// (reviewer agents) exit immediately after verdict set, killing the thread
/// before the merge completes. Running synchronously is safe — the caller
/// is `finalize_projected_verdict` at the tail of verdict set, so a few
/// seconds of git fast-forward latency does not block any upstream work.
fn maybe_auto_merge_if_ready(record: &PrLifecycleRecord, source: &str) {
    if record.pr_state != PrLifecycleState::MergeReady {
        return;
    }

    maybe_auto_merge_if_ready_inner(record, source);
}

fn maybe_auto_merge_if_ready_inner(record: &PrLifecycleRecord, source: &str) {
    let identity = match projection_store::load_pr_identity(&record.owner_repo, record.pr_number) {
        Ok(value) => value,
        Err(err) => {
            let _ = apply_event(
                &record.owner_repo,
                record.pr_number,
                &record.current_sha,
                &LifecycleEventKind::MergeFailed {
                    reason: format!("failed to load identity for auto-merge: {err}"),
                },
            );
            return;
        },
    };
    let Some(identity) = identity else {
        let _ = apply_event(
            &record.owner_repo,
            record.pr_number,
            &record.current_sha,
            &LifecycleEventKind::MergeFailed {
                reason: "missing identity for auto-merge".to_string(),
            },
        );
        return;
    };
    let Some(branch) = identity
        .branch
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        let _ = apply_event(
            &record.owner_repo,
            record.pr_number,
            &record.current_sha,
            &LifecycleEventKind::MergeFailed {
                reason: "missing branch in identity for auto-merge".to_string(),
            },
        );
        return;
    };

    let merge_dir = identity
        .worktree
        .as_deref()
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let merge_evidence = match load_merge_evidence_binding(
        &record.owner_repo,
        record.pr_number,
        &record.current_sha,
    ) {
        Ok(value) => value,
        Err(err) => {
            let _ = apply_event(
                &record.owner_repo,
                record.pr_number,
                &record.current_sha,
                &LifecycleEventKind::MergeFailed { reason: err },
            );
            return;
        },
    };

    let merge_result = (|| -> Result<MergeProjectionContext, String> {
        sync_local_main_with_origin(&merge_dir)?;
        let pre_merge_main = git_stdout_checked(
            &merge_dir,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                "refs/heads/main^{commit}",
            ],
        )?;
        try_fast_forward_main(&merge_dir, branch, &record.current_sha)?;
        let persisted_receipt = match persist_signed_merge_receipt(
            &record.owner_repo,
            record.pr_number,
            &record.current_sha,
            &record.current_sha,
            &merge_evidence,
        ) {
            Ok(value) => value,
            Err(err) => {
                if let Err(rollback_err) = rollback_local_main_after_receipt_failure(
                    &merge_dir,
                    &pre_merge_main,
                    &record.current_sha,
                ) {
                    return Err(format!(
                        "failed to emit signed merge receipt: {err}; additionally failed to roll back local main: {rollback_err}"
                    ));
                }
                return Err(format!(
                    "failed to emit signed merge receipt: {err}; local main rolled back to pre-merge commit"
                ));
            },
        };
        push_local_main_to_origin(&merge_dir, &record.current_sha)?;
        Ok(MergeProjectionContext {
            owner_repo: record.owner_repo.clone(),
            pr_number: record.pr_number,
            merge_sha: record.current_sha.clone(),
            source_branch: branch.to_string(),
            merge_receipt_hash: persisted_receipt.content_hash,
            merged_at_iso: persisted_receipt.merged_at_iso,
            gate_job_id: merge_evidence.gate_job_id.clone(),
            gate_receipt_id: merge_evidence.gate_receipt_id.clone(),
            policy_hash: merge_evidence.policy_hash.clone(),
            gate_evidence_hashes: merge_evidence.gate_evidence_hashes.clone(),
            verdict_hashes: merge_evidence.verdict_hashes.clone(),
        })
    })();
    match merge_result {
        Ok(projection_context) => {
            if let Err(err) = apply_event(
                &record.owner_repo,
                record.pr_number,
                &record.current_sha,
                &LifecycleEventKind::Merged {
                    source: source.to_string(),
                },
            ) {
                eprintln!(
                    "WARNING: auto-merge succeeded but failed to persist merged lifecycle event for PR #{}: {err}",
                    record.pr_number
                );
            }
            if let Err(err) =
                project_merge_to_all_sinks_with_retry(&merge_dir, &projection_context, 3)
            {
                eprintln!(
                    "WARNING: local merge completed but projection sinks reported errors for PR #{}: {err}",
                    record.pr_number
                );
                if let Err(event_err) = apply_event(
                    &record.owner_repo,
                    record.pr_number,
                    &record.current_sha,
                    &LifecycleEventKind::ProjectionFailed {
                        reason: err.clone(),
                    },
                ) {
                    eprintln!(
                        "WARNING: failed to persist projection_failed lifecycle event for PR #{}: {event_err}",
                        record.pr_number
                    );
                }
                if let Err(persist_err) = save_merge_projection_pending(
                    &record.owner_repo,
                    record.pr_number,
                    &record.current_sha,
                    &projection_context,
                    &err,
                    1,
                ) {
                    eprintln!(
                        "WARNING: failed to persist pending merge projection record for PR #{}: {persist_err}",
                        record.pr_number
                    );
                }
            } else if let Err(err) = projection_store::clear_merge_projection_pending(
                &record.owner_repo,
                record.pr_number,
                &record.current_sha,
            ) {
                eprintln!(
                    "WARNING: merge projection succeeded for PR #{} but failed to clear pending projection record: {err}",
                    record.pr_number
                );
            }
            cleanup_merged_branch_local_state(&merge_dir, branch, identity.worktree.as_deref());
        },
        Err(err) => {
            if let Err(event_err) = apply_event(
                &record.owner_repo,
                record.pr_number,
                &record.current_sha,
                &LifecycleEventKind::MergeFailed {
                    reason: err.clone(),
                },
            ) {
                eprintln!(
                    "WARNING: failed to persist merge_failed lifecycle event for PR #{}: {} (merge error: {err})",
                    record.pr_number, event_err
                );
            }
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FacRequiredStatusProjection {
    state: &'static str,
    description: &'static str,
}

fn derive_fac_required_status_projection(
    snapshot: &verdict_projection::VerdictProjectionSnapshot,
) -> FacRequiredStatusProjection {
    if snapshot.fail_closed {
        return FacRequiredStatusProjection {
            state: "failure",
            description: FAC_STATUS_DESCRIPTION_FAIL_CLOSED,
        };
    }

    match snapshot.overall_decision.as_str() {
        "deny" => FacRequiredStatusProjection {
            state: "failure",
            description: FAC_STATUS_DESCRIPTION_DENIED,
        },
        "approve" => FacRequiredStatusProjection {
            state: "success",
            description: FAC_STATUS_DESCRIPTION_SUCCESS,
        },
        _ => FacRequiredStatusProjection {
            state: "pending",
            description: FAC_STATUS_DESCRIPTION_PENDING,
        },
    }
}

fn fac_required_status_projection_for_decision(decision: &str) -> FacRequiredStatusProjection {
    match decision {
        "deny" => FacRequiredStatusProjection {
            state: "failure",
            description: FAC_STATUS_DESCRIPTION_DENIED,
        },
        "approve" => FacRequiredStatusProjection {
            state: "success",
            description: FAC_STATUS_DESCRIPTION_SUCCESS,
        },
        _ => FacRequiredStatusProjection {
            state: "failure",
            description: FAC_STATUS_DESCRIPTION_FAIL_CLOSED,
        },
    }
}

fn load_fac_required_status_contexts() -> Result<Vec<String>, String> {
    let contexts = crate::commands::fac_pr::load_local_required_status_contexts(None)?;
    if contexts.is_empty() {
        return Err("local required-status policy contains no contexts".to_string());
    }
    Ok(contexts)
}

fn load_fac_required_status_snapshot(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<verdict_projection::VerdictProjectionSnapshot, String> {
    verdict_projection::load_verdict_projection_snapshot(owner_repo, pr_number, head_sha)?
        .ok_or_else(|| {
            format!("missing verdict projection snapshot for PR #{pr_number} SHA {head_sha}")
        })
}

fn project_fac_required_status_to_contexts_with<F>(
    contexts: &[String],
    mut project_context: F,
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    if contexts.is_empty() {
        return Err("cannot project required status without at least one context".to_string());
    }
    for context in contexts {
        project_context(context)?;
    }
    Ok(())
}

fn project_fac_required_status_with<FSnapshot, FProjectContext>(
    _owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    required_status_contexts: &[String],
    mut load_snapshot: FSnapshot,
    mut project_context: FProjectContext,
) -> Result<(), String>
where
    FSnapshot: FnMut() -> Result<verdict_projection::VerdictProjectionSnapshot, String>,
    FProjectContext: FnMut(&str, FacRequiredStatusProjection) -> Result<(), String>,
{
    let mut last_mismatch: Option<(FacRequiredStatusProjection, FacRequiredStatusProjection)> =
        None;
    for _ in 0..FAC_STATUS_PROJECTION_MAX_ATTEMPTS {
        let projection = derive_fac_required_status_projection(&load_snapshot()?);
        project_fac_required_status_to_contexts_with(required_status_contexts, |context| {
            project_context(context, projection)
        })?;
        let observed_projection = derive_fac_required_status_projection(&load_snapshot()?);
        if observed_projection == projection {
            return Ok(());
        }
        last_mismatch = Some((projection, observed_projection));
    }
    let mismatch_detail = last_mismatch.map_or_else(
        || "projection mismatch unavailable".to_string(),
        |(written, observed)| {
            format!(
                "last_written={} last_observed={}",
                written.state, observed.state
            )
        },
    );
    Err(format!(
        "concurrent verdict updates prevented stable FAC required-status projection for PR #{pr_number} SHA {head_sha} after {FAC_STATUS_PROJECTION_MAX_ATTEMPTS} attempts ({mismatch_detail})"
    ))
}

fn project_fac_required_status(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<(), String> {
    let required_status_contexts = load_fac_required_status_contexts()?;
    let target_url = format!("https://github.com/{owner_repo}/pull/{pr_number}");
    project_fac_required_status_with(
        owner_repo,
        pr_number,
        head_sha,
        &required_status_contexts,
        || load_fac_required_status_snapshot(owner_repo, pr_number, head_sha),
        |context, projection| {
            github_projection::upsert_commit_status(
                owner_repo,
                head_sha,
                context,
                projection.state,
                projection.description,
                Some(&target_url),
            )
        },
    )
}

fn project_fac_required_status_with_projection(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    projection: FacRequiredStatusProjection,
) -> Result<(), String> {
    let required_status_contexts = load_fac_required_status_contexts()?;
    let target_url = format!("https://github.com/{owner_repo}/pull/{pr_number}");
    project_fac_required_status_to_contexts_with(&required_status_contexts, |context| {
        github_projection::upsert_commit_status(
            owner_repo,
            head_sha,
            context,
            projection.state,
            projection.description,
            Some(&target_url),
        )
    })
}

fn project_fac_required_status_for_decision(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    decision: &str,
) -> Result<(), String> {
    let projection = fac_required_status_projection_for_decision(decision);
    project_fac_required_status_with_projection(owner_repo, pr_number, head_sha, projection)
}

fn project_fac_required_status_fail_closed(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<(), String> {
    project_fac_required_status_with_projection(
        owner_repo,
        pr_number,
        head_sha,
        FacRequiredStatusProjection {
            state: "failure",
            description: FAC_STATUS_DESCRIPTION_FAIL_CLOSED,
        },
    )
}

fn finalize_projected_verdict(
    projected: &verdict_projection::PersistedVerdictProjection,
    fallback_dimension: &str,
    run_id: &str,
    auto_source: Option<&str>,
) -> Result<(), String> {
    replay_pending_merge_projection_for_repo(&projected.owner_repo);

    let lifecycle_dimension =
        resolve_lifecycle_dimension(&projected.review_state_type, fallback_dimension)?;
    let reduced = apply_event(
        &projected.owner_repo,
        projected.pr_number,
        &projected.head_sha,
        &LifecycleEventKind::VerdictSet {
            dimension: lifecycle_dimension.clone(),
            decision: projected.decision.clone(),
        },
    )?;
    if let Some(source) = auto_source {
        apply_event(
            &projected.owner_repo,
            projected.pr_number,
            &projected.head_sha,
            &LifecycleEventKind::VerdictAutoDerived {
                dimension: lifecycle_dimension,
                decision: projected.decision.clone(),
                source: source.to_string(),
            },
        )?;
    }

    if let Err(err) = project_fac_required_status(
        &projected.owner_repo,
        projected.pr_number,
        &projected.head_sha,
    ) {
        eprintln!(
            "WARNING: failed to project required FAC status check for PR #{} sha {}: {err}",
            projected.pr_number, projected.head_sha
        );
        let fallback_result = match load_fac_required_status_snapshot(
            &projected.owner_repo,
            projected.pr_number,
            &projected.head_sha,
        ) {
            Ok(snapshot) => project_fac_required_status_with_projection(
                &projected.owner_repo,
                projected.pr_number,
                &projected.head_sha,
                derive_fac_required_status_projection(&snapshot),
            ),
            Err(snapshot_err) => {
                eprintln!(
                    "WARNING: failed to load overall verdict snapshot for fallback status projection on PR #{} sha {}: {snapshot_err}; projecting fail-closed status",
                    projected.pr_number, projected.head_sha
                );
                project_fac_required_status_fail_closed(
                    &projected.owner_repo,
                    projected.pr_number,
                    &projected.head_sha,
                )
            },
        };
        if let Err(fallback_err) = fallback_result {
            eprintln!(
                "WARNING: failed fallback FAC required-status projection for PR #{} sha {}: {fallback_err}",
                projected.pr_number, projected.head_sha
            );
        }
    }

    maybe_auto_merge_if_ready(&reduced, auto_source.unwrap_or("explicit_verdict_set"));

    let authority = TerminationAuthority::new(
        &projected.owner_repo,
        projected.pr_number,
        &projected.review_state_type,
        &projected.head_sha,
        run_id,
        projected.decision_comment_id,
        &projected.decision_author,
        &now_iso8601(),
        &projected.decision_signature,
    );
    let home = apm2_home_dir()?;
    dispatch::write_completion_receipt_for_verdict(&home, &authority, &projected.decision)?;
    Ok(())
}

fn finalize_auto_verdict_candidate(
    candidate: &AutoVerdictCandidate,
) -> Result<AutoVerdictFinalizeResult, String> {
    if !candidate_matches_current_pr_head(candidate)? {
        return Ok(AutoVerdictFinalizeResult::Pending);
    }

    let dimension = normalize_verdict_dimension(&candidate.review_type)?.to_string();
    let existing = verdict_projection::resolve_verdict_for_dimension(
        &candidate.owner_repo,
        candidate.pr_number,
        &candidate.head_sha,
        &dimension,
    )?;
    if existing.is_some() {
        return Ok(AutoVerdictFinalizeResult::SkippedExisting);
    }

    let Some(decision) = derive_auto_verdict_decision_from_findings(
        &candidate.owner_repo,
        candidate.pr_number,
        &candidate.head_sha,
        &dimension,
    )?
    else {
        return Ok(AutoVerdictFinalizeResult::Pending);
    };

    let (model_id, backend_id) =
        state::load_review_run_state_strict(candidate.pr_number, &candidate.review_type)?
            .filter(|state| {
                state.run_id == candidate.run_id
                    && state.head_sha.eq_ignore_ascii_case(&candidate.head_sha)
            })
            .map_or((None, None), |state| (state.model_id, state.backend_id));

    let projected = verdict_projection::persist_verdict_projection_local_only(
        &candidate.owner_repo,
        Some(candidate.pr_number),
        Some(&candidate.head_sha),
        &dimension,
        decision,
        Some("auto_derived_by_reaper_from_findings"),
        model_id.as_deref(),
        backend_id.as_deref(),
    )?;
    finalize_projected_verdict(&projected, &dimension, &candidate.run_id, Some("reaper"))?;

    Ok(AutoVerdictFinalizeResult::Applied)
}

fn finalize_auto_verdict_candidates(candidates: Vec<AutoVerdictCandidate>) -> AutoVerdictOutcome {
    let mut outcome = AutoVerdictOutcome::default();
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        let key = format!(
            "{}::{}::{}::{}",
            candidate.owner_repo.to_ascii_lowercase(),
            candidate.pr_number,
            candidate.head_sha.to_ascii_lowercase(),
            candidate.review_type.to_ascii_lowercase(),
        );
        if !seen.insert(key) {
            continue;
        }

        match finalize_auto_verdict_candidate(&candidate) {
            Ok(AutoVerdictFinalizeResult::Applied) => {
                outcome.applied = outcome.applied.saturating_add(1);
            },
            Ok(AutoVerdictFinalizeResult::Pending) => {
                outcome.pending = outcome.pending.saturating_add(1);
            },
            Ok(AutoVerdictFinalizeResult::SkippedExisting) => {
                outcome.skipped_existing = outcome.skipped_existing.saturating_add(1);
            },
            Err(err) => {
                outcome.failed = outcome.failed.saturating_add(1);
                eprintln!(
                    "WARNING: auto-verdict finalization failed for PR #{} repo={} type={} sha={}: {err}",
                    candidate.pr_number,
                    candidate.owner_repo,
                    candidate.review_type,
                    candidate.head_sha
                );
            },
        }
    }
    outcome
}

fn enqueue_auto_verdict_candidates(candidates: Vec<AutoVerdictCandidate>, source: &'static str) {
    if candidates.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        let outcome = finalize_auto_verdict_candidates(candidates);
        if outcome.failed > 0 {
            eprintln!(
                "WARNING: reaper auto-verdict encountered {} errors in deferred worker ({source})",
                outcome.failed
            );
        }
    });
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
            | S::Merged
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
                S::GatesPassed
                | S::ReviewsDispatched
                | S::ReviewInProgress
                | S::VerdictPending
                | S::VerdictApprove
                | S::VerdictDeny
                | S::MergeReady
                | S::Stuck => {
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
        LifecycleEventKind::VerdictAutoDerived {
            dimension,
            decision,
            ..
        } => {
            let _ = normalize_verdict_dimension(dimension)?;
            let _ = normalize_verdict_decision(decision)?;
            Ok(state.pr_state)
        },
        LifecycleEventKind::MergeFailed { .. } => match state.pr_state {
            S::MergeReady | S::VerdictApprove | S::VerdictPending | S::Stuck => Ok(S::Stuck),
            _ => Err(format!(
                "illegal transition: {} + merge_failed",
                state.pr_state.as_str()
            )),
        },
        LifecycleEventKind::Merged { .. } => match state.pr_state {
            S::MergeReady | S::Merged => Ok(S::Merged),
            _ => Err(format!(
                "illegal transition: {} + merged",
                state.pr_state.as_str()
            )),
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
        LifecycleEventKind::VerdictAutoDerived {
            dimension,
            decision,
            source,
        } => serde_json::json!({
            "dimension": dimension,
            "decision": decision,
            "source": source,
        }),
        LifecycleEventKind::MergeFailed { reason }
        | LifecycleEventKind::Quarantined { reason }
        | LifecycleEventKind::ProjectionFailed { reason } => serde_json::json!({
            "reason": reason,
        }),
        LifecycleEventKind::Merged { source } => serde_json::json!({
            "source": source,
        }),
        LifecycleEventKind::AgentCrashed { agent_type } => serde_json::json!({
            "agent_type": agent_type.as_str(),
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
        serde_json::json!({"from":"untracked|pushed|gates_running|gates_passed|gates_failed|reviews_dispatched|review_in_progress|verdict_pending|verdict_approve|verdict_deny|merge_ready|merged|stuck|stale|recovering","event":"push_observed","to":"pushed"}),
        serde_json::json!({"from":"pushed|gates_failed|recovering","event":"gates_started","to":"gates_running"}),
        serde_json::json!({"from":"gates_running","event":"gates_passed","to":"gates_passed"}),
        serde_json::json!({"from":"gates_running","event":"gates_failed","to":"gates_failed"}),
        serde_json::json!({"from":"gates_passed|reviews_dispatched|review_in_progress|verdict_pending","event":"reviews_dispatched","to":"reviews_dispatched"}),
        serde_json::json!({"from":"reviews_dispatched|review_in_progress|verdict_pending","event":"reviewer_spawned","to":"review_in_progress"}),
        serde_json::json!({"from":"gates_passed|reviews_dispatched|review_in_progress|verdict_pending|verdict_approve|verdict_deny|merge_ready","event":"verdict_set","to":"verdict_pending|verdict_deny|merge_ready"}),
        serde_json::json!({"from":"*","event":"verdict_auto_derived","to":"self"}),
        serde_json::json!({"from":"merge_ready|verdict_approve|verdict_pending|stuck","event":"merge_failed","to":"stuck"}),
        serde_json::json!({"from":"merge_ready|merged","event":"merged","to":"merged"}),
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
                "verdict_approve","verdict_deny","merge_ready","merged",
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

fn reset_lifecycle_record_to_pushed(record: &mut PrLifecycleRecord, head_sha: &str) {
    let previous_state = record.pr_state.as_str().to_string();
    record.current_sha = head_sha.to_ascii_lowercase();
    record.pr_state = PrLifecycleState::Pushed;
    record.error_budget_used = 0;
    record.retry_budget_remaining = default_retry_budget();
    record.verdicts.clear();
    record.append_event(
        head_sha,
        "recover_reset_lifecycle",
        serde_json::json!({
            "previous_state": previous_state,
            "new_state": "pushed",
            "source": "doctor_fix",
        }),
    );
}

pub(super) fn reap_stale_agents_for_pr_bypass_hmac(
    owner_repo: &str,
    pr_number: u32,
    force: bool,
) -> Result<BypassReapOutcome, String> {
    let (before_active_agents, after_active_agents, reaped_agents, auto_candidates) = {
        let _lock = acquire_registry_lock()?;
        let mut registry = load_registry_bypass_hmac(force)?;
        let before_active_agents = active_agents_for_pr(&registry, owner_repo, pr_number);
        let reap_result =
            reap_registry_stale_entries_scoped(&mut registry, Some((owner_repo, pr_number)));
        save_registry_bypass_hmac(&registry)?;
        let after_active_agents = active_agents_for_pr(&registry, owner_repo, pr_number);
        (
            before_active_agents,
            after_active_agents,
            reap_result.reaped,
            reap_result.auto_verdict_candidates,
        )
    };

    let auto_outcome = finalize_auto_verdict_candidates(auto_candidates);
    Ok(BypassReapOutcome {
        before_active_agents,
        after_active_agents,
        reaped_agents,
        auto_verdict_applied: auto_outcome.applied,
        auto_verdict_pending: auto_outcome.pending,
        auto_verdict_skipped_existing: auto_outcome.skipped_existing,
        auto_verdict_failed: auto_outcome.failed,
    })
}

pub(super) fn repair_registry_integrity_for_pr_bypass_hmac(
    owner_repo: &str,
    pr_number: u32,
    force: bool,
) -> Result<BypassRegistryRepairOutcome, String> {
    let (_lock, mut registry, quarantined_registry_path, quarantine_reason) = {
        let lock = acquire_registry_lock()?;
        let path = registry_path()?;
        let bytes = match fs::read(&path) {
            Ok(value) => Some(value),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(format!(
                    "failed to read agent registry {}: {err}",
                    path.display()
                ));
            },
        };

        let mut quarantined_registry_path = None;
        let mut quarantine_reason = None;
        let mut registry = AgentRegistry::default();

        if let Some(bytes) = bytes {
            match serde_json::from_slice::<AgentRegistry>(&bytes) {
                Ok(parsed) if parsed.schema != AGENT_REGISTRY_SCHEMA => {
                    if !force {
                        return Err(format!(
                            "unexpected agent registry schema {} at {}",
                            parsed.schema,
                            path.display()
                        ));
                    }
                    quarantined_registry_path =
                        quarantine_registry()?.map(|value| value.display().to_string());
                    quarantine_reason = Some(format!(
                        "unexpected agent registry schema {}",
                        parsed.schema
                    ));
                },
                Ok(parsed) => match verify_registry_integrity_without_rotation(&parsed) {
                    Ok(()) => {
                        registry = parsed;
                    },
                    Err(err) => {
                        if !force {
                            return Err(err);
                        }
                        quarantined_registry_path =
                            quarantine_registry()?.map(|value| value.display().to_string());
                        quarantine_reason = Some(err);
                    },
                },
                Err(err) => {
                    if !force {
                        return Err(format!(
                            "failed to parse agent registry {}: {err}",
                            path.display()
                        ));
                    }
                    quarantined_registry_path =
                        quarantine_registry()?.map(|value| value.display().to_string());
                    quarantine_reason = Some(format!("failed to parse agent registry: {err}"));
                },
            }
        }

        (lock, registry, quarantined_registry_path, quarantine_reason)
    };

    let before_total_entries = registry.entries.len();
    let before_active_agents = active_agents_for_pr(&registry, owner_repo, pr_number);
    let reap_result =
        reap_registry_stale_entries_scoped(&mut registry, Some((owner_repo, pr_number)));
    save_registry_bypass_hmac(&registry)?;
    let after_total_entries = registry.entries.len();
    let after_active_agents = active_agents_for_pr(&registry, owner_repo, pr_number);

    Ok(BypassRegistryRepairOutcome {
        before_active_agents,
        after_active_agents,
        before_total_entries,
        after_total_entries,
        reaped_agents: reap_result.reaped,
        quarantined_registry_path,
        quarantine_reason,
    })
}

pub(super) fn reset_lifecycle_for_pr_bypass_hmac(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    force: bool,
) -> Result<BypassLifecycleResetOutcome, String> {
    validate_expected_head_sha(head_sha)?;
    let _state_lock = acquire_pr_state_lock(owner_repo, pr_number)?;
    let mut record = load_pr_state_bypass_hmac(owner_repo, pr_number, head_sha, force)?;
    let before_state = record.pr_state.as_str().to_string();
    let previous_event_seq = record.last_event_seq;
    reset_lifecycle_record_to_pushed(&mut record, head_sha);
    save_pr_state_bypass_hmac(&record)?;
    Ok(BypassLifecycleResetOutcome {
        before_state,
        after_state: record.pr_state.as_str().to_string(),
        previous_event_seq,
        current_event_seq: record.last_event_seq,
    })
}

pub fn enforce_pr_capacity(owner_repo: &str, pr_number: u32) -> Result<(), String> {
    let (active, auto_verdict_candidates) = {
        let _lock = acquire_registry_lock()?;
        let mut registry = load_registry()?;
        let reap_result = reap_registry_stale_entries(&mut registry);
        let active = active_agents_for_pr(&registry, owner_repo, pr_number);
        save_registry(&registry)?;
        (active, reap_result.auto_verdict_candidates)
    };
    enqueue_auto_verdict_candidates(auto_verdict_candidates, "enforce_pr_capacity");
    if active >= MAX_ACTIVE_AGENTS_PER_PR {
        return Err(format!(
            "at_capacity: PR #{pr_number} already has {active} active agents (max={MAX_ACTIVE_AGENTS_PER_PR})"
        ));
    }
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

    let token = generate_completion_token();
    let mut capacity_error = None;
    let auto_verdict_candidates = {
        let _lock = acquire_registry_lock()?;
        let mut registry = load_registry()?;
        let reap_result = reap_registry_stale_entries(&mut registry);
        let active = active_agents_for_pr(&registry, owner_repo, pr_number);
        let auto_verdict_candidates = reap_result.auto_verdict_candidates;
        if active >= MAX_ACTIVE_AGENTS_PER_PR {
            save_registry(&registry)?;
            capacity_error = Some(format!(
                "at_capacity: PR #{pr_number} already has {active} active agents (max={MAX_ACTIVE_AGENTS_PER_PR})"
            ));
        } else {
            let token_hash = token_hash(&token);
            let expires_at =
                (Utc::now() + token_ttl()).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
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
        }
        auto_verdict_candidates
    };
    enqueue_auto_verdict_candidates(auto_verdict_candidates, "register_agent_spawn");

    if let Some(err) = capacity_error {
        return Err(err);
    }
    Ok(token)
}

pub(super) fn bind_reviewer_runtime(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    review_type: &str,
    run_id: &str,
    pid: u32,
    proc_start_time: Option<u64>,
) -> Result<(), String> {
    validate_expected_head_sha(sha)?;
    if run_id.trim().is_empty() {
        return Err("cannot bind reviewer runtime with empty run_id".to_string());
    }
    let Some(agent_type) = reviewer_agent_type(review_type) else {
        return Ok(());
    };

    let auto_verdict_candidates = {
        let _lock = acquire_registry_lock()?;
        let mut registry = load_registry()?;
        let reap_result =
            reap_registry_stale_entries_scoped(&mut registry, Some((owner_repo, pr_number)));
        let agent_id = tracked_agent_id(owner_repo, pr_number, run_id, agent_type);
        let mut found = false;
        for entry in &mut registry.entries {
            if entry.agent_id != agent_id {
                continue;
            }
            entry.sha = sha.to_ascii_lowercase();
            entry.state = TrackedAgentState::Running;
            entry.pid = Some(pid);
            entry.proc_start_time = proc_start_time.or_else(|| state::get_process_start_time(pid));
            entry.completed_at = None;
            entry.reap_reason = None;
            found = true;
            break;
        }

        if !found {
            let token_hash = token_hash(&generate_completion_token());
            let expires_at =
                (Utc::now() + token_ttl()).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            registry.entries.push(TrackedAgent {
                agent_id,
                owner_repo: owner_repo.to_ascii_lowercase(),
                pr_number,
                sha: sha.to_ascii_lowercase(),
                run_id: run_id.to_string(),
                agent_type,
                state: TrackedAgentState::Running,
                started_at: now_iso8601(),
                completed_at: None,
                pid: Some(pid),
                proc_start_time: proc_start_time.or_else(|| state::get_process_start_time(pid)),
                completion_token_hash: token_hash,
                token_expires_at: expires_at,
                completion_status: None,
                completion_summary: None,
                reap_reason: None,
            });
        }

        registry.updated_at = now_iso8601();
        save_registry(&registry)?;
        reap_result.auto_verdict_candidates
    };
    enqueue_auto_verdict_candidates(auto_verdict_candidates, "bind_reviewer_runtime");
    Ok(())
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

#[allow(clippy::too_many_arguments)]
pub fn register_reviewer_dispatch(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
    review_type: &str,
    run_id: Option<&str>,
    pid: Option<u32>,
    proc_start_time: Option<u64>,
    emit_reviews_dispatched: bool,
    clear_projection_verdicts: bool,
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
    let mut cleared_projection_backup = None;
    if emit_reviews_dispatched {
        if clear_projection_verdicts {
            match verdict_projection::clear_dimension_verdicts_for_sha_with_backup(
                owner_repo, pr_number, sha,
            ) {
                Ok(backup) => {
                    cleared_projection_backup = backup;
                },
                Err(err) => {
                    let rollback_reason = "rollback:clear_projection_verdicts_failed";
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
                },
            }
        }

        if let Err(err) = apply_event(
            owner_repo,
            pr_number,
            sha,
            &LifecycleEventKind::ReviewsDispatched,
        ) {
            let rollback_reason = "rollback:lifecycle_reviews_dispatched_failed";
            let rollback_result = rollback_registered_reviewer_dispatch(
                owner_repo,
                pr_number,
                run_id,
                agent_type,
                pid,
                rollback_reason,
            );
            let restore_result = cleared_projection_backup
                .take()
                .map(verdict_projection::restore_dimension_verdicts_for_sha)
                .transpose()
                .map(|_| ());
            match (rollback_result, restore_result) {
                (Ok(()), Ok(())) => return Err(err),
                (Ok(()), Err(restore_err)) => {
                    return Err(format!(
                        "{err}; additionally failed to restore cleared verdict projection: {restore_err}"
                    ));
                },
                (Err(rollback_err), Ok(())) => {
                    return Err(format!(
                        "{err}; additionally failed to rollback registry entry run_id={run_id}: {rollback_err}"
                    ));
                },
                (Err(rollback_err), Err(restore_err)) => {
                    return Err(format!(
                        "{err}; additionally failed to rollback registry entry run_id={run_id}: {rollback_err}; additionally failed to restore cleared verdict projection: {restore_err}"
                    ));
                },
            }
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
        let rollback_result = rollback_registered_reviewer_dispatch(
            owner_repo,
            pr_number,
            run_id,
            agent_type,
            pid,
            rollback_reason,
        );
        let restore_result = cleared_projection_backup
            .take()
            .map(verdict_projection::restore_dimension_verdicts_for_sha)
            .transpose()
            .map(|_| ());
        match (rollback_result, restore_result) {
            (Ok(()), Ok(())) => return Err(err),
            (Ok(()), Err(restore_err)) => {
                return Err(format!(
                    "{err}; additionally failed to restore cleared verdict projection: {restore_err}"
                ));
            },
            (Err(rollback_err), Ok(())) => {
                return Err(format!(
                    "{err}; additionally failed to rollback registry entry run_id={run_id}: {rollback_err}"
                ));
            },
            (Err(rollback_err), Err(restore_err)) => {
                return Err(format!(
                    "{err}; additionally failed to rollback registry entry run_id={run_id}: {rollback_err}; additionally failed to restore cleared verdict projection: {restore_err}"
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
    model_id: Option<&str>,
    backend_id: Option<&str>,
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
        model_id,
        backend_id,
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
    model_id: Option<&str>,
    backend_id: Option<&str>,
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
        model_id,
        backend_id,
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
    let caller_pid = current_process_id();
    let called_by_review_agent = termination_state
        .as_ref()
        .and_then(|state| state.pid)
        .is_some_and(|reviewer_pid| is_descendant_of_pid(caller_pid, reviewer_pid));
    let finalize_verdict = || -> Result<u8, String> {
        finalize_projected_verdict(&projected, dimension, &run_id, None)?;
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{
        AgentType, AutoVerdictCandidate, AutoVerdictFinalizeResult,
        FAC_STATUS_PROJECTION_MAX_ATTEMPTS, LifecycleEventKind, MERGE_EVIDENCE_END,
        MERGE_EVIDENCE_START, MergeEvidenceBinding, PrLifecycleState, TrackedAgentState,
        acquire_registry_lock, active_agents_for_pr, apply_event, bind_reviewer_runtime,
        compute_merge_receipt_changeset_digest, delete_remote_branch_projection,
        derive_auto_verdict_decision_from_findings, derive_fac_required_status_projection,
        enforce_pr_capacity, fac_required_status_projection_for_decision,
        finalize_auto_verdict_candidate, load_fac_required_status_contexts, load_registry,
        normalize_hash_list, normalize_sha256_hex_digest,
        project_fac_required_status_to_contexts_with, project_fac_required_status_with,
        register_agent_spawn, register_reviewer_dispatch, save_registry,
        sync_local_main_with_origin, token_hash, try_fast_forward_main, upsert_marker_section,
    };
    use crate::commands::fac_review::lifecycle::tracked_agent_id;
    use crate::commands::fac_review::state::{
        get_process_start_time, load_review_run_completion_receipt, write_review_run_state,
    };
    use crate::commands::fac_review::types::{ReviewRunState, ReviewRunStatus};
    use crate::commands::fac_review::verdict_projection::resolve_verdict_for_dimension;

    static UNIQUE_PR_COUNTER: AtomicU32 = AtomicU32::new(0);
    static RUN_PR_BASE: OnceLock<u32> = OnceLock::new();

    fn next_pr() -> u32 {
        let base = *RUN_PR_BASE.get_or_init(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let pid = u128::from(std::process::id());
            let mixed = now ^ (pid << 32);
            1_000_000u32 + ((mixed % 3_000_000_000u128) as u32)
        });
        base.saturating_add(UNIQUE_PR_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    fn next_repo(tag: &str, pr: u32) -> String {
        format!("example/{tag}-{pr}")
    }

    fn verdict_snapshot(
        overall_decision: &str,
        fail_closed: bool,
    ) -> super::verdict_projection::VerdictProjectionSnapshot {
        super::verdict_projection::VerdictProjectionSnapshot {
            schema: "apm2.review.verdict.v1".to_string(),
            pr_number: 77,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            overall_decision: overall_decision.to_string(),
            fail_closed,
            dimensions: Vec::new(),
            errors: Vec::new(),
            source_comment_id: None,
            source_comment_url: None,
            updated_at: "2026-02-17T00:00:00Z".to_string(),
        }
    }

    fn git_checked(dir: &std::path::Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("run git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn required_status_projection_reports_failure_for_denied_verdict() {
        let snapshot = verdict_snapshot("deny", false);
        let projection = derive_fac_required_status_projection(&snapshot);
        assert_eq!(projection.state, "failure");
    }

    #[test]
    fn required_status_projection_reports_success_for_approved_verdict() {
        let snapshot = verdict_snapshot("approve", false);
        let projection = derive_fac_required_status_projection(&snapshot);
        assert_eq!(projection.state, "success");
    }

    #[test]
    fn required_status_projection_reports_pending_for_partial_verdict() {
        let snapshot = verdict_snapshot("pending", false);
        let projection = derive_fac_required_status_projection(&snapshot);
        assert_eq!(projection.state, "pending");
    }

    #[test]
    fn required_status_projection_fails_closed_when_snapshot_integrity_fails() {
        let snapshot = verdict_snapshot("approve", true);
        let projection = derive_fac_required_status_projection(&snapshot);
        assert_eq!(projection.state, "failure");
    }

    #[test]
    fn required_status_projection_fallback_reports_failure_for_deny() {
        let projection = fac_required_status_projection_for_decision("deny");
        assert_eq!(projection.state, "failure");
    }

    #[test]
    fn required_status_projection_contexts_come_from_local_authoritative_policy() {
        let expected = crate::commands::fac_pr::load_local_required_status_contexts(None)
            .expect("load authoritative contexts");
        let actual = load_fac_required_status_contexts().expect("load projection contexts");
        assert_eq!(actual, expected);
        assert!(
            !actual.is_empty(),
            "projection requires at least one context"
        );
    }

    #[test]
    fn required_status_projection_projects_every_context() {
        let contexts = vec!["ctx/one".to_string(), "ctx/two".to_string()];
        let seen = std::cell::RefCell::new(Vec::new());

        project_fac_required_status_to_contexts_with(&contexts, |context| {
            seen.borrow_mut().push(context.to_string());
            Ok(())
        })
        .expect("projection to contexts should succeed");

        assert_eq!(&*seen.borrow(), &contexts);
    }

    #[test]
    fn required_status_projection_rejects_empty_context_list() {
        let err = project_fac_required_status_to_contexts_with(&[], |_| Ok(()))
            .expect_err("empty context set must fail");
        assert!(err.contains("at least one context"));
    }

    #[test]
    fn required_status_projection_retries_until_snapshot_stabilizes() {
        let contexts = vec!["apm2 / Forge Admission Cycle".to_string()];
        let snapshot_calls = std::cell::Cell::new(0usize);
        let projected_states = std::cell::RefCell::new(Vec::<String>::new());
        let result = project_fac_required_status_with(
            "guardian-intelligence/apm2",
            718,
            "0123456789abcdef0123456789abcdef01234567",
            &contexts,
            || {
                let call = snapshot_calls.get();
                snapshot_calls.set(call + 1);
                let snapshot = match call {
                    0 => verdict_snapshot("pending", false),
                    _ => verdict_snapshot("approve", false),
                };
                Ok(snapshot)
            },
            |_, projection| {
                projected_states
                    .borrow_mut()
                    .push(projection.state.to_string());
                Ok(())
            },
        );

        result.expect("projection should converge to latest verdict state");
        assert_eq!(
            &*projected_states.borrow(),
            &vec!["pending".to_string(), "success".to_string()]
        );
    }

    #[test]
    fn required_status_projection_fails_when_snapshot_never_stabilizes() {
        let contexts = vec!["apm2 / Forge Admission Cycle".to_string()];
        let snapshot_calls = std::cell::Cell::new(0usize);
        let projected_states = std::cell::RefCell::new(Vec::<String>::new());
        let err = project_fac_required_status_with(
            "guardian-intelligence/apm2",
            718,
            "0123456789abcdef0123456789abcdef01234567",
            &contexts,
            || {
                let call = snapshot_calls.get();
                snapshot_calls.set(call + 1);
                let snapshot = if call % 2 == 0 {
                    verdict_snapshot("pending", false)
                } else {
                    verdict_snapshot("approve", false)
                };
                Ok(snapshot)
            },
            |_, projection| {
                projected_states
                    .borrow_mut()
                    .push(projection.state.to_string());
                Ok(())
            },
        )
        .expect_err("projection must fail closed when verdict state keeps drifting");

        assert!(err.contains("concurrent verdict updates"));
        assert_eq!(
            projected_states.borrow().len(),
            FAC_STATUS_PROJECTION_MAX_ATTEMPTS
        );
    }

    fn git_stdout(dir: &std::path::Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("run git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn init_git_repo_for_merge_tests() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path();
        git_checked(dir, &["init"]);
        git_checked(dir, &["config", "user.email", "test@example.com"]);
        git_checked(dir, &["config", "user.name", "apm2-test"]);
        fs::write(dir.join("README.md"), "base\n").expect("write base file");
        git_checked(dir, &["add", "README.md"]);
        git_checked(dir, &["commit", "-m", "base"]);
        git_checked(dir, &["branch", "-M", "main"]);
        temp
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
    fn reviews_dispatched_clears_lifecycle_verdicts() {
        let pr = next_pr();
        let repo = next_repo("reviews-dispatched-clear", pr);
        let sha = "11223344556677889900aabbccddeeff00112233";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("passed");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::ReviewsDispatched).expect("dispatch");
        let approved = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "security".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("security approve");
        assert!(approved.verdicts.contains_key("security"));

        let reset =
            apply_event(&repo, pr, sha, &LifecycleEventKind::ReviewsDispatched).expect("restart");
        assert!(reset.verdicts.is_empty());
    }

    #[test]
    fn reducer_does_not_reenter_merge_ready_with_single_verdict_after_restart() {
        let pr = next_pr();
        let repo = next_repo("restart-single-verdict", pr);
        let sha = "44556677889900aabbccddeeff00112233445566";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("passed");
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
        let restarted =
            apply_event(&repo, pr, sha, &LifecycleEventKind::ReviewsDispatched).expect("restart");
        assert!(restarted.verdicts.is_empty());

        let post_restart = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "code-quality".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("quality approve after restart");
        assert_eq!(post_restart.pr_state, PrLifecycleState::VerdictPending);
    }

    #[test]
    fn reducer_allows_verdict_set_from_gates_passed() {
        let pr = next_pr();
        let repo = next_repo("gates-passed-verdict", pr);
        let sha = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("passed");

        let verdict = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "security".to_string(),
                decision: "deny".to_string(),
            },
        )
        .expect("verdict from gates_passed");
        assert_eq!(verdict.pr_state, PrLifecycleState::VerdictDeny);
    }

    #[test]
    fn reducer_transitions_merge_ready_to_merged_on_merged_event() {
        let pr = next_pr();
        let repo = next_repo("merged-transition", pr);
        let sha = "1111111111111111111111111111111111111111";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("passed");
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
        let _ = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "code-quality".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("quality approve");
        let merged = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::Merged {
                source: "test".to_string(),
            },
        )
        .expect("merged");
        assert_eq!(merged.pr_state, PrLifecycleState::Merged);
    }

    #[test]
    fn merge_failed_event_moves_state_to_stuck() {
        let pr = next_pr();
        let repo = next_repo("merge-failed-transition", pr);
        let sha = "1212121212121212121212121212121212121212";
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("passed");
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
        let _ = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::VerdictSet {
                dimension: "code-quality".to_string(),
                decision: "approve".to_string(),
            },
        )
        .expect("quality approve");
        let stuck = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::MergeFailed {
                reason: "non-fast-forward".to_string(),
            },
        )
        .expect("merge_failed");
        assert_eq!(stuck.pr_state, PrLifecycleState::Stuck);
    }

    #[test]
    fn try_fast_forward_main_succeeds_without_main_worktree_checked_out() {
        let temp = init_git_repo_for_merge_tests();
        let dir = temp.path();

        git_checked(dir, &["checkout", "-b", "ticket"]);
        fs::write(dir.join("README.md"), "feature\n").expect("write feature change");
        git_checked(dir, &["add", "README.md"]);
        git_checked(dir, &["commit", "-m", "feature"]);
        let ticket_sha = git_stdout(dir, &["rev-parse", "HEAD"]);

        try_fast_forward_main(dir, "ticket", &ticket_sha).expect("fast-forward main");
        let main_sha = git_stdout(dir, &["rev-parse", "refs/heads/main"]);
        assert_eq!(main_sha, ticket_sha.to_ascii_lowercase());
    }

    #[test]
    fn try_fast_forward_main_rejects_non_fast_forward_merge() {
        let temp = init_git_repo_for_merge_tests();
        let dir = temp.path();

        git_checked(dir, &["checkout", "-b", "ticket"]);
        fs::write(dir.join("README.md"), "ticket\n").expect("write ticket change");
        git_checked(dir, &["add", "README.md"]);
        git_checked(dir, &["commit", "-m", "ticket"]);
        let ticket_sha = git_stdout(dir, &["rev-parse", "HEAD"]);

        git_checked(dir, &["checkout", "main"]);
        fs::write(dir.join("README.md"), "main\n").expect("write main change");
        git_checked(dir, &["add", "README.md"]);
        git_checked(dir, &["commit", "-m", "main"]);

        let err = try_fast_forward_main(dir, "ticket", &ticket_sha)
            .expect_err("non-fast-forward merge should be rejected");
        assert!(err.contains("non-fast-forward merge required"));
    }

    #[test]
    fn try_fast_forward_main_rejects_expected_sha_mismatch() {
        let temp = init_git_repo_for_merge_tests();
        let dir = temp.path();

        git_checked(dir, &["checkout", "-b", "ticket"]);
        fs::write(dir.join("README.md"), "feature\n").expect("write feature change");
        git_checked(dir, &["add", "README.md"]);
        git_checked(dir, &["commit", "-m", "feature"]);

        let err = try_fast_forward_main(dir, "ticket", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect_err("sha mismatch should be rejected");
        assert!(err.contains("does not match lifecycle SHA"));
    }

    #[test]
    fn try_fast_forward_main_does_not_reset_dirty_main_worktree() {
        let temp = init_git_repo_for_merge_tests();
        let dir = temp.path();
        let main_worktree = temp.path().join("main-worktree");
        let main_worktree_str = main_worktree.to_string_lossy().to_string();

        git_checked(dir, &["checkout", "-b", "ticket"]);
        git_checked(dir, &["worktree", "add", &main_worktree_str, "main"]);

        fs::write(main_worktree.join("README.md"), "dirty-main\n")
            .expect("write dirty main worktree change");
        fs::write(dir.join("README.md"), "feature\n").expect("write ticket change");
        git_checked(dir, &["add", "README.md"]);
        git_checked(dir, &["commit", "-m", "feature"]);
        let ticket_sha = git_stdout(dir, &["rev-parse", "HEAD"]);

        try_fast_forward_main(dir, "ticket", &ticket_sha).expect("fast-forward main");
        let main_sha = git_stdout(dir, &["rev-parse", "refs/heads/main"]);
        assert_eq!(main_sha, ticket_sha.to_ascii_lowercase());

        let dirty_contents =
            fs::read_to_string(main_worktree.join("README.md")).expect("read dirty main file");
        assert_eq!(dirty_contents, "dirty-main\n");
    }

    #[test]
    fn sync_local_main_with_origin_recreates_missing_local_main_ref() {
        let temp = init_git_repo_for_merge_tests();
        let dir = temp.path();
        let origin_path = dir.join("origin.git");
        let origin_str = origin_path.to_string_lossy().to_string();

        git_checked(dir, &["clone", "--bare", ".", &origin_str]);
        git_checked(dir, &["remote", "add", "origin", &origin_str]);
        git_checked(
            dir,
            &[
                "fetch",
                "origin",
                "refs/heads/main:refs/remotes/origin/main",
            ],
        );
        git_checked(dir, &["checkout", "-b", "ticket"]);
        git_checked(dir, &["branch", "-D", "main"]);

        let missing_main = Command::new("git")
            .args([
                "rev-parse",
                "--verify",
                "--quiet",
                "refs/heads/main^{commit}",
            ])
            .current_dir(dir)
            .output()
            .expect("verify local main is missing");
        assert_eq!(missing_main.status.code(), Some(1));

        sync_local_main_with_origin(dir).expect("sync should recreate local main");
        let recreated_main = git_stdout(dir, &["rev-parse", "refs/heads/main"]);
        let remote_main = git_stdout(dir, &["rev-parse", "refs/remotes/origin/main"]);
        assert_eq!(recreated_main, remote_main);
    }

    #[test]
    fn sync_local_main_with_origin_fails_closed_when_origin_main_is_ahead() {
        let temp = init_git_repo_for_merge_tests();
        let dir = temp.path();
        let origin_path = dir.join("origin.git");
        let origin_str = origin_path.to_string_lossy().to_string();

        git_checked(dir, &["clone", "--bare", ".", &origin_str]);
        git_checked(dir, &["remote", "add", "origin", &origin_str]);
        git_checked(
            dir,
            &[
                "fetch",
                "origin",
                "refs/heads/main:refs/remotes/origin/main",
            ],
        );

        let upstream_clone = tempfile::tempdir().expect("tempdir for upstream clone");
        let upstream_clone_str = upstream_clone.path().to_string_lossy().to_string();
        git_checked(dir, &["clone", &origin_str, &upstream_clone_str]);
        git_checked(
            upstream_clone.path(),
            &["config", "user.email", "test@example.com"],
        );
        git_checked(upstream_clone.path(), &["config", "user.name", "apm2-test"]);
        fs::write(upstream_clone.path().join("README.md"), "origin ahead\n")
            .expect("write origin ahead update");
        git_checked(upstream_clone.path(), &["add", "README.md"]);
        git_checked(upstream_clone.path(), &["commit", "-m", "origin ahead"]);
        git_checked(upstream_clone.path(), &["push", "origin", "main"]);

        let err =
            sync_local_main_with_origin(dir).expect_err("origin-ahead state must fail closed");
        assert!(err.contains("origin/main is ahead"));
    }

    #[test]
    fn delete_remote_branch_projection_is_idempotent_when_branch_missing() {
        let temp = init_git_repo_for_merge_tests();
        let dir = temp.path();
        let origin_path = dir.join("origin.git");
        let origin_str = origin_path.to_string_lossy().to_string();

        git_checked(dir, &["clone", "--bare", ".", &origin_str]);
        git_checked(dir, &["remote", "add", "origin", &origin_str]);

        delete_remote_branch_projection(dir, "ticket/missing")
            .expect("missing remote branch should not fail projection");
    }

    #[test]
    fn normalize_sha256_hex_digest_rejects_invalid_payload() {
        let err = normalize_sha256_hex_digest("b3-256:abc", "decision hash")
            .expect_err("non-hex signature digest must be rejected");
        assert!(err.contains("64-char hex digest"));
    }

    #[test]
    fn merge_receipt_changeset_digest_binds_gate_and_verdict_hashes() {
        let binding = MergeEvidenceBinding {
            gate_job_id: "job-1".to_string(),
            gate_receipt_id: "receipt-1".to_string(),
            policy_hash: format!("b3-256:{}", "ab".repeat(32)),
            gate_evidence_hashes: normalize_hash_list(&[
                format!("b3-256:{}", "01".repeat(32)),
                format!("b3-256:{}", "02".repeat(32)),
            ]),
            verdict_hashes: normalize_hash_list(&[
                format!("b3-256:{}", "03".repeat(32)),
                format!("b3-256:{}", "04".repeat(32)),
            ]),
        };
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let digest_a = compute_merge_receipt_changeset_digest("example/repo", 42, sha, &binding)
            .expect("compute digest A");

        let mut binding_b = binding;
        binding_b.verdict_hashes = normalize_hash_list(&[format!("b3-256:{}", "ff".repeat(32))]);
        let digest_b = compute_merge_receipt_changeset_digest("example/repo", 42, sha, &binding_b)
            .expect("compute digest B");

        assert_ne!(
            digest_a, digest_b,
            "changeset digest must change when verdict hashes change"
        );
    }

    #[test]
    fn merge_evidence_section_replaces_existing_marker_block() {
        let old =
            format!("intro\n\n{MERGE_EVIDENCE_START}\nold content\n{MERGE_EVIDENCE_END}\n\nfooter");
        let replacement = format!("{MERGE_EVIDENCE_START}\nnew content\n{MERGE_EVIDENCE_END}");
        let updated =
            upsert_marker_section(&old, MERGE_EVIDENCE_START, MERGE_EVIDENCE_END, &replacement);
        assert!(updated.contains("intro"));
        assert!(updated.contains("footer"));
        assert!(updated.contains("new content"));
        assert!(!updated.contains("old content"));
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
    fn at_capacity_ignores_duplicate_active_entries_for_same_agent_id() {
        let pr = next_pr();
        let repo = next_repo("capacity-dedup", pr);
        let sha = "2828282828282828282828282828282828282828";
        let run_id = format!("pr{pr}-security-s1-28282828");
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &run_id,
            AgentType::ReviewerSecurity,
            None,
            None,
        )
        .expect("first");

        {
            let _lock = acquire_registry_lock().expect("registry lock");
            let mut registry = load_registry().expect("registry");
            let entry_id = tracked_agent_id(&repo, pr, &run_id, AgentType::ReviewerSecurity);
            let duplicate = registry
                .entries
                .iter()
                .find(|entry| entry.agent_id == entry_id)
                .cloned()
                .expect("existing entry to duplicate");
            registry.entries.push(duplicate);
            save_registry(&registry).expect("save duplicate");
        }

        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-quality-s2-28282828"),
            AgentType::ReviewerQuality,
            None,
            None,
        )
        .expect("second unique slot should still be allowed");
        let err = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-impl-s3-28282828"),
            AgentType::Implementer,
            None,
            None,
        )
        .expect_err("third unique slot should fail");
        assert!(err.contains("at_capacity"));
    }

    #[test]
    fn register_agent_spawn_reaps_no_pid_entries_with_invalid_started_at() {
        let pr = next_pr();
        let repo = next_repo("capacity-invalid-started-at", pr);
        let sha = "2929292929292929292929292929292929292929";
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-impl-s1-29292929"),
            AgentType::Implementer,
            None,
            None,
        )
        .expect("first");
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-orchestrator-s2-29292929"),
            AgentType::Orchestrator,
            None,
            None,
        )
        .expect("second");

        {
            let _lock = acquire_registry_lock().expect("registry lock");
            let mut registry = load_registry().expect("registry");
            for entry in &mut registry.entries {
                if entry.owner_repo.eq_ignore_ascii_case(&repo)
                    && entry.pr_number == pr
                    && matches!(
                        entry.state,
                        TrackedAgentState::Dispatched | TrackedAgentState::Running
                    )
                {
                    entry.started_at = "not-a-timestamp".to_string();
                    entry.pid = None;
                    entry.proc_start_time = None;
                }
            }
            save_registry(&registry).expect("save invalid started_at");
        }

        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-gate-s3-29292929"),
            AgentType::GateExecutor,
            None,
            None,
        )
        .expect("invalid started_at rows should be reaped before capacity check");

        let registry = load_registry().expect("registry after reaping");
        let reaped = registry
            .entries
            .iter()
            .filter(|entry| entry.owner_repo.eq_ignore_ascii_case(&repo) && entry.pr_number == pr)
            .filter(|entry| {
                entry.state == TrackedAgentState::Reaped
                    && entry.reap_reason.as_deref() == Some("stale_without_pid_invalid_started_at")
            })
            .count();
        assert!(
            reaped >= 2,
            "expected invalid no-pid rows to be reaped, got {reaped}"
        );
    }

    #[test]
    fn enforce_pr_capacity_reaps_stale_no_pid_entries() {
        let pr = next_pr();
        let repo = next_repo("capacity-reap-no-pid", pr);
        let sha = "3333333333333333333333333333333333333333";
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-security-s1-33333333"),
            AgentType::ReviewerSecurity,
            None,
            None,
        )
        .expect("first");
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &format!("pr{pr}-quality-s2-33333333"),
            AgentType::ReviewerQuality,
            None,
            None,
        )
        .expect("second");

        {
            let _lock = acquire_registry_lock().expect("registry lock");
            let mut registry = load_registry().expect("registry");
            let stale_started_at = "2000-01-01T00:00:00Z".to_string();
            for entry in &mut registry.entries {
                if entry.owner_repo.eq_ignore_ascii_case(&repo)
                    && entry.pr_number == pr
                    && matches!(
                        entry.state,
                        TrackedAgentState::Dispatched | TrackedAgentState::Running
                    )
                {
                    entry.started_at = stale_started_at.clone();
                    entry.pid = None;
                    entry.proc_start_time = None;
                }
            }
            save_registry(&registry).expect("save stale registry");
        }

        enforce_pr_capacity(&repo, pr).expect("stale no-pid entries should be reaped");

        let registry = load_registry().expect("registry after reaping");
        assert_eq!(active_agents_for_pr(&registry, &repo, pr), 0);
        let reaped = registry
            .entries
            .iter()
            .filter(|entry| entry.owner_repo.eq_ignore_ascii_case(&repo) && entry.pr_number == pr)
            .filter(|entry| entry.state == TrackedAgentState::Reaped)
            .count();
        assert!(
            reaped >= 2,
            "expected stale reviewer entries to be reaped, got {reaped}"
        );
    }

    #[test]
    fn enforce_pr_capacity_hydrates_pid_from_run_state_for_no_pid_reviewer() {
        let pr = next_pr();
        let repo = next_repo("capacity-hydrate-no-pid", pr);
        let sha = "4444444444444444444444444444444444444444";
        let run_id = format!("pr{pr}-security-s1-44444444");
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &run_id,
            AgentType::ReviewerSecurity,
            None,
            None,
        )
        .expect("spawn");

        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sentinel process");
        let pid = child.id();
        let proc_start_time = get_process_start_time(pid);
        let run_state = ReviewRunState {
            run_id: run_id.clone(),
            owner_repo: repo.clone(),
            pr_number: pr,
            head_sha: sha.to_string(),
            review_type: "security".to_string(),
            reviewer_role: "fac_reviewer".to_string(),
            started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            status: ReviewRunStatus::Alive,
            terminal_reason: None,
            model_id: Some("test-model".to_string()),
            backend_id: Some("test-backend".to_string()),
            restart_count: 0,
            nudge_count: 0,
            sequence_number: 1,
            previous_run_id: None,
            previous_head_sha: None,
            pid: Some(pid),
            proc_start_time,
            integrity_hmac: None,
        };
        write_review_run_state(&run_state).expect("write run-state");

        enforce_pr_capacity(&repo, pr).expect("capacity check");

        let registry = load_registry().expect("registry");
        let entry_id = tracked_agent_id(&repo, pr, &run_id, AgentType::ReviewerSecurity);
        let entry = registry
            .entries
            .iter()
            .find(|value| value.agent_id == entry_id)
            .expect("registry entry");
        assert_eq!(entry.state, TrackedAgentState::Running);
        assert_eq!(entry.pid, Some(pid));
        assert_eq!(entry.proc_start_time, proc_start_time);

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn enforce_pr_capacity_reaps_no_pid_reviewer_when_run_state_is_terminal() {
        let pr = next_pr();
        let repo = next_repo("capacity-terminal-run-state", pr);
        let sha = "4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a";
        let run_id = format!("pr{pr}-security-s1-4a4a4a4a");
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &run_id,
            AgentType::ReviewerSecurity,
            None,
            None,
        )
        .expect("spawn");

        let run_state = ReviewRunState {
            run_id: run_id.clone(),
            owner_repo: repo.clone(),
            pr_number: pr,
            head_sha: sha.to_string(),
            review_type: "security".to_string(),
            reviewer_role: "fac_reviewer".to_string(),
            started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            status: ReviewRunStatus::Done,
            terminal_reason: Some("completed".to_string()),
            model_id: Some("test-model".to_string()),
            backend_id: Some("test-backend".to_string()),
            restart_count: 0,
            nudge_count: 0,
            sequence_number: 1,
            previous_run_id: None,
            previous_head_sha: None,
            pid: None,
            proc_start_time: None,
            integrity_hmac: None,
        };
        write_review_run_state(&run_state).expect("write terminal run-state");

        enforce_pr_capacity(&repo, pr).expect("capacity check");

        let registry = load_registry().expect("registry");
        let entry_id = tracked_agent_id(&repo, pr, &run_id, AgentType::ReviewerSecurity);
        let entry = registry
            .entries
            .iter()
            .find(|value| value.agent_id == entry_id)
            .expect("registry entry");
        assert_eq!(entry.state, TrackedAgentState::Reaped);
        assert_eq!(entry.reap_reason.as_deref(), Some("run_state_terminal"));
    }

    #[test]
    fn bind_reviewer_runtime_sets_running_pid_for_registered_slot() {
        let pr = next_pr();
        let repo = next_repo("bind-runtime", pr);
        let sha = "5555555555555555555555555555555555555555";
        let run_id = format!("pr{pr}-quality-s1-55555555");
        let _ = register_agent_spawn(
            &repo,
            pr,
            sha,
            &run_id,
            AgentType::ReviewerQuality,
            None,
            None,
        )
        .expect("spawn");

        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sentinel process");
        let pid = child.id();
        let proc_start_time = get_process_start_time(pid);

        bind_reviewer_runtime(&repo, pr, sha, "quality", &run_id, pid, proc_start_time)
            .expect("bind runtime");

        let registry = load_registry().expect("registry");
        let entry_id = tracked_agent_id(&repo, pr, &run_id, AgentType::ReviewerQuality);
        let entry = registry
            .entries
            .iter()
            .find(|value| value.agent_id == entry_id)
            .expect("registry entry");
        assert_eq!(entry.state, TrackedAgentState::Running);
        assert_eq!(entry.pid, Some(pid));
        assert_eq!(entry.proc_start_time, proc_start_time);

        let _ = child.kill();
        let _ = child.wait();
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

        let err = register_reviewer_dispatch(
            &repo,
            pr,
            sha,
            "security",
            Some(&run_id),
            None,
            None,
            true,
            false,
        )
        .expect_err("register should fail because lifecycle transition is illegal from untracked");
        assert!(err.contains("illegal transition"));

        let registry = load_registry().expect("registry");
        assert_eq!(active_agents_for_pr(&registry, &repo, pr), 0);
        let entry_id = tracked_agent_id(&repo, pr, &run_id, AgentType::ReviewerSecurity);
        if let Some(entry) = registry
            .entries
            .iter()
            .find(|value| value.agent_id == entry_id)
        {
            assert_eq!(entry.state, TrackedAgentState::Reaped);
            assert_eq!(
                entry.reap_reason.as_deref(),
                Some("rollback:lifecycle_reviews_dispatched_failed")
            );
        }
    }

    #[test]
    fn register_reviewer_dispatch_restores_projection_when_reviews_dispatched_fails() {
        let pr = next_pr();
        let repo = next_repo("dispatch-restore-projection", pr);
        let sha = "9999999999999999999999999999999999999999";
        let run_id = format!("pr{pr}-security-s1-99999999");

        super::verdict_projection::persist_verdict_projection_local_only(
            &repo,
            Some(pr),
            Some(sha),
            "security",
            "approve",
            Some("seed"),
            None,
            None,
        )
        .expect("seed security projection");
        super::verdict_projection::persist_verdict_projection_local_only(
            &repo,
            Some(pr),
            Some(sha),
            "code-quality",
            "approve",
            Some("seed"),
            None,
            None,
        )
        .expect("seed quality projection");
        assert_eq!(
            resolve_verdict_for_dimension(&repo, pr, sha, "security").expect("load security"),
            Some("PASS".to_string())
        );

        let err = register_reviewer_dispatch(
            &repo,
            pr,
            sha,
            "security",
            Some(&run_id),
            None,
            None,
            true,
            true,
        )
        .expect_err("register should fail because lifecycle transition is illegal from untracked");
        assert!(err.contains("illegal transition"));

        assert_eq!(
            resolve_verdict_for_dimension(&repo, pr, sha, "security").expect("load security"),
            Some("PASS".to_string())
        );
        assert_eq!(
            resolve_verdict_for_dimension(&repo, pr, sha, "code-quality")
                .expect("load code-quality"),
            Some("PASS".to_string())
        );
    }

    #[test]
    fn auto_verdict_derivation_uses_findings_severity_policy() {
        let pr = next_pr();
        let repo = next_repo("auto-verdict-derive", pr);
        let sha = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        let none =
            derive_auto_verdict_decision_from_findings(&repo, pr, sha, "security").expect("none");
        assert_eq!(none, None);

        let _ = super::findings_store::append_dimension_finding(
            &repo,
            pr,
            sha,
            "security",
            "major",
            "major issue",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "test",
        )
        .expect("append major");
        let deny =
            derive_auto_verdict_decision_from_findings(&repo, pr, sha, "security").expect("deny");
        assert_eq!(deny, Some("deny"));

        let pr2 = next_pr();
        let repo2 = next_repo("auto-verdict-derive-minor", pr2);
        let _ = super::findings_store::append_dimension_finding(
            &repo2,
            pr2,
            sha,
            "security",
            "minor",
            "minor issue",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "test",
        )
        .expect("append minor");
        let approve = derive_auto_verdict_decision_from_findings(&repo2, pr2, sha, "security")
            .expect("approve");
        assert_eq!(approve, Some("approve"));
    }

    #[test]
    fn auto_verdict_finalization_persists_local_verdict_and_completion_receipt() {
        let pr = next_pr();
        let repo = next_repo("auto-verdict-finalize", pr);
        let sha = "ffffffffffffffffffffffffffffffffffffffff";
        let run_id = format!("pr{pr}-security-s1-ffffffff");

        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::PushObserved).expect("push");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesStarted).expect("gates");
        let _ = apply_event(&repo, pr, sha, &LifecycleEventKind::GatesPassed).expect("passed");
        let _ =
            apply_event(&repo, pr, sha, &LifecycleEventKind::ReviewsDispatched).expect("dispatch");
        let _ = apply_event(
            &repo,
            pr,
            sha,
            &LifecycleEventKind::ReviewerSpawned {
                review_type: "security".to_string(),
            },
        )
        .expect("spawned");

        let _ = super::findings_store::append_dimension_finding(
            &repo,
            pr,
            sha,
            "security",
            "major",
            "major issue",
            None,
            None,
            None,
            None,
            Some("reviewer"),
            None,
            None,
            None,
            "test",
        )
        .expect("append major");

        let result = finalize_auto_verdict_candidate(&AutoVerdictCandidate {
            owner_repo: repo.clone(),
            pr_number: pr,
            head_sha: sha.to_string(),
            review_type: "security".to_string(),
            run_id: run_id.clone(),
        })
        .expect("auto finalize");
        assert!(matches!(result, AutoVerdictFinalizeResult::Applied));

        let verdict = resolve_verdict_for_dimension(&repo, pr, sha, "security")
            .expect("resolve verdict")
            .expect("verdict present");
        assert_eq!(verdict, "FAIL");

        let receipt = load_review_run_completion_receipt(pr, "security")
            .expect("load completion receipt")
            .expect("completion receipt exists");
        assert_eq!(receipt.repo, repo);
        assert_eq!(receipt.head_sha, sha);
        assert_eq!(receipt.run_id, run_id);
        assert_eq!(receipt.decision, "deny");
    }
}
