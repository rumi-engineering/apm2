//! FAC (Forge Admission Cycle) productivity CLI commands.
//!
//! This module implements the `apm2 fac` subcommands for ledger/CAS-oriented
//! debugging and productivity per TCK-00333 and RFC-0019.
//!
//! # Commands
//!
//! - `apm2 fac work status <work_id>` - Show projection-backed work status via
//!   daemon
//! - `apm2 fac work list` - List projection-known work items via daemon
//! - `apm2 fac role-launch <work_id> <role> --role-spec-hash ...` - Perform
//!   fail-closed hash-binding admission checks and emit launch receipt
//! - `apm2 fac episode inspect <episode_id>` - Show episode details and tool
//!   log index
//! - `apm2 fac receipt show <receipt_hash>` - Show receipt from CAS
//! - `apm2 fac context rebuild <role> <episode_id>` - Rebuild role-scoped
//!   context
//! - `apm2 fac review run --pr <N>` - Run FAC review orchestration (parallel,
//!   multi-model; defaults from local branch mapping when omitted)
//! - `apm2 fac review prepare` - Materialize local review inputs (diff/history)
//! - `apm2 fac review findings` - Retrieve SHA-bound review findings in a
//!   structured FAC-native format
//! - `apm2 fac review verdict` - Show/set SHA-bound approve/deny verdicts per
//!   review dimension
//! - `apm2 fac services status` - Inspect daemon/worker managed service health
//! - `apm2 fac restart --pr <PR_NUMBER>` - Intelligent pipeline restart from
//!   optimal point
//! - `apm2 fac recover --pr <N>` - Repair/reconcile local FAC lifecycle state
//! - `apm2 fac review tail` - Tail FAC review NDJSON telemetry stream
//!
//! # Design
//!
//! Most commands operate directly on ledger and CAS files for crash-only
//! debugging. Work lifecycle authority surfaces (`fac work status/list`) route
//! through daemon operator IPC so runtime authority remains projection-backed.
//!
//! # Exit Codes (RFC-0018)
//!
//! - 0: Success
//! - 10: Validation error
//! - 12: Not found
//! - 1: Generic error
//!
//! # Contract References
//!
//! - TCK-00333: FAC productivity CLI/scripts (ledger/CAS oriented debug UX)
//! - RFC-0019: FAC v0 requirements

use std::path::{Path, PathBuf};
use std::process::Command;

use apm2_core::fac::service_user_gate::QueueWriteMode;
use apm2_core::fac::{
    FacUnitLiveness, GcActionKind, GcPlan, LANE_ENV_DIRS, LaneCorruptMarkerV1, LaneInitReceiptV1,
    LaneLeaseV1, LaneManager, LaneState, LaneStatusV1, LogRetentionConfig, MAX_LOG_DIR_ENTRIES,
    ORPHANED_SYSTEMD_UNIT_REASON_CODE, PROJECTION_ARTIFACT_SCHEMA_IDENTIFIER, ProcessIdentity,
    REVIEW_ARTIFACT_SCHEMA_IDENTIFIER, RefusedDeleteReceipt, SUMMARY_RECEIPT_SCHEMA,
    SafeRmtreeError, SafeRmtreeOutcome, TOOL_EXECUTION_RECEIPT_SCHEMA, TOOL_LOG_INDEX_V1_SCHEMA,
    ToolLogIndexV1, check_fac_unit_liveness, execute_gc, plan_gc_with_log_retention,
    safe_rmtree_v1, safe_rmtree_v1_with_entry_limit, verify_pid_identity,
};
use apm2_core::ledger::{EventRecord, Ledger, LedgerError};
use apm2_daemon::protocol::WorkRole;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::client::protocol::{OperatorClient, ProtocolClientError};
pub use crate::commands::fac_broker::BrokerArgs;
use crate::commands::role_launch::{self, RoleLaunchArgs};
use crate::commands::{
    fac_broker, fac_economics, fac_gc, fac_policy, fac_pr, fac_preflight, fac_quarantine,
    fac_review,
};
use crate::exit_codes::{codes as exit_codes, map_protocol_error};

// =============================================================================
// Constants
// =============================================================================

/// Default number of events to scan from the head of the ledger.
/// This limits the number of events scanned (not the sequence ID) to prevent
/// unbounded memory/time usage in very large ledgers.
const DEFAULT_SCAN_LIMIT: u64 = 10_000;

/// Maximum CAS file size to read (64 MiB).
/// Prevents `DoS` via excessively large CAS artifacts.
const MAX_CAS_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// Default ledger path relative to data directory.
const DEFAULT_LEDGER_FILENAME: &str = "ledger.db";

/// Default CAS path relative to data directory.
const DEFAULT_CAS_DIRNAME: &str = "cas";

const SERVICES_UNIT_NAMES: [&str; 2] = ["apm2-daemon.service", "apm2-worker.service"];
const SERVICE_STATUS_PROPERTIES: [&str; 7] = [
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "MainPID",
    "ActiveEnterTimestampMonotonic",
    "WatchdogUSec",
];
const FAC_DOCTOR_SYSTEM_SCHEMA: &str = "apm2.fac.doctor.system.v1";
const FAC_DOCTOR_SYSTEM_FIX_SCHEMA: &str = "apm2.fac.doctor.system_fix.v1";
const MAX_TMP_SCRUB_ENTRIES: usize = 250_000;

// =============================================================================
// Command Types
// =============================================================================

/// FAC command group.
#[derive(Debug, Args)]
pub struct FacCommand {
    /// Emit JSON/JSONL output.
    #[arg(long, default_value_t = true)]
    pub json: bool,

    /// Path to ledger database (defaults to `$APM2_DATA_DIR/ledger.db`).
    #[arg(long)]
    pub ledger_path: Option<PathBuf>,

    /// Path to CAS directory (defaults to `$APM2_DATA_DIR/cas`).
    #[arg(long)]
    pub cas_path: Option<PathBuf>,

    /// Bypass the service-user ownership gate for direct queue/receipt writes.
    ///
    /// By default, non-service-user processes are denied direct filesystem
    /// writes to FAC queue and receipt directories (TCK-00577). This flag
    /// disables that check for backward compatibility and development.
    ///
    /// **NOT recommended for production deployments.** Use broker-mediated
    /// enqueue instead.
    #[arg(long, default_value_t = false)]
    pub unsafe_local_write: bool,

    #[command(subcommand)]
    pub subcommand: FacSubcommand,
}

impl FacCommand {
    /// Derive the requested queue write mode from the `--unsafe-local-write`
    /// flag.
    ///
    /// Returns `QueueWriteMode::UnsafeLocalWrite` if the flag is set,
    /// otherwise `QueueWriteMode::ServiceUserOnly` (the secure default).
    ///
    /// Note: `ServiceUserOnly` may still auto-bypass in user-mode inside
    /// `check_queue_write_permission` (TCK-00657).
    #[must_use]
    pub const fn queue_write_mode(&self) -> QueueWriteMode {
        if self.unsafe_local_write {
            QueueWriteMode::UnsafeLocalWrite
        } else {
            QueueWriteMode::ServiceUserOnly
        }
    }
}

/// FAC subcommands.
#[derive(Debug, Subcommand)]
pub enum FacSubcommand {
    /// Run all evidence gates locally with resource-bounded test execution.
    ///
    /// Validates fmt, clippy, doc, test safety, tests (bounded), workspace
    /// integrity, and review artifact lint. Results are cached per-SHA so
    /// `apm2 fac pipeline` can skip gates that already passed.
    ///
    /// Throughput model: FAC executes full gates in single-flight mode so one
    /// caller gets maximal host compute (CPU/memory/IO) until completion.
    /// Concurrent callers coalesce/queue rather than splitting compute across
    /// multiple heavyweight test runs.
    #[command(hide = true)]
    Gates(GatesArgs),

    /// Internal: CI preflight checks for credential posture and workflow trust.
    #[command(hide = true)]
    Preflight(PreflightArgs),

    /// Query projection-backed work authority via daemon operator IPC.
    ///
    /// Displays work status or lists work items from runtime projection state.
    /// This is the authoritative runtime surface for work lifecycle reads.
    Work(WorkArgs),

    /// Check daemon health and prerequisites.
    Doctor(DoctorArgs),

    /// Install apm2 globally and realign binary paths.
    ///
    /// Runs `cargo install --path crates/apm2-cli --force`, re-links
    /// `~/.local/bin/apm2 -> ~/.cargo/bin/apm2`, restarts daemon and
    /// worker services. Prevents INV-PADOPT-004 binary drift recurrence.
    Install(InstallArgs),

    /// Report daemon and worker managed service health.
    Services(ServicesArgs),

    /// Launch a FAC role with explicit hash-bound admission checks.
    ///
    /// Requires non-zero, CAS-resolvable role/context/capability/policy hashes
    /// and emits a replay-verifiable launch receipt on success.
    RoleLaunch(RoleLaunchArgs),

    /// Inspect episode details and tool log index.
    ///
    /// Shows episode metadata and tool execution summary from ledger events.
    /// Allows inspecting tool log index entries without raw log parsing.
    Episode(EpisodeArgs),

    /// Job receipt operations: show, list, status lookup, and reindex.
    ///
    /// Provides index-accelerated receipt lookups. The receipt index is a
    /// non-authoritative cache — corrupt or missing index triggers automatic
    /// rebuild from the receipt store.
    Receipts(ReceiptArgs),

    /// Rebuild role-scoped context deterministically.
    ///
    /// Reconstructs the context pack for a role+episode combination from
    /// ledger events and CAS artifacts. Useful for debugging and replay.
    Context(ContextArgs),

    /// Manage FAC execution lanes.
    ///
    /// Shows lane states derived from lock state, lease records, and PID
    /// liveness. Lanes are the sole concurrency primitive for FAC execution.
    Lane(LaneArgs),

    /// Push code and create/update PR (lean push).
    ///
    /// Pushes to remote, creates or updates a PR from ticket YAML metadata,
    /// blocks on evidence gates, synchronizes ruleset projection, and
    /// dispatches reviews.
    Push(PushArgs),

    /// Restart the evidence/review pipeline from the optimal point.
    ///
    /// Reads local authoritative FAC verdict artifacts and determines whether
    /// to re-run evidence gates, dispatch reviews, or no-op.
    Restart(RestartArgs),

    /// Repair or reconcile local FAC lifecycle state.
    ///
    /// Reaps stale agent registry entries and can refresh local PR identity
    /// from authoritative remote state.
    #[command(hide = true)]
    Recover(RecoverArgs),

    /// Show local pipeline, evidence, and review log paths.
    ///
    /// Lists all FAC log files under `~/.apm2/` with sizes.
    /// Use `--pr <N>` to filter to a specific pull request.
    Logs(LogsArgs),

    /// Internal: background evidence+review pipeline (hidden from help).
    #[command(hide = true)]
    Pipeline(PipelineArgs),

    /// Run and observe FAC review orchestration for pull requests.
    ///
    /// Provides VPS-oriented review execution and observability with
    /// parallel `security + quality` orchestration, model fallback, and
    /// NDJSON telemetry under `~/.apm2`.
    Review(ReviewArgs),

    /// Queue consumer with RFC-0028 authorization + RFC-0029 admission gating.
    ///
    /// Scans `$APM2_HOME/queue/pending/` for job specs, validates against
    /// RFC-0028 channel context tokens and RFC-0029 admission, then
    /// atomically claims and executes valid jobs.
    Worker(WorkerArgs),

    /// Job lifecycle management (cancel).
    ///
    /// Provides cancellation semantics for pending, claimed, and running jobs.
    /// Cancelling a pending job moves it to `cancelled/` with a receipt.
    /// Cancelling a claimed/running job enqueues a `stop_revoke` job that
    /// kills the active systemd unit and marks the target job cancelled.
    Job(JobArgs),

    /// GitHub App credential management and PR operations.
    ///
    /// Provides `auth-setup` for bootstrapping credentials and
    /// `auth-check` for verifying they are accessible.
    Pr(fac_pr::PrArgs),
    /// Inspect FAC broker state and health.
    Broker(BrokerArgs),
    /// Garbage collect stale FAC artifacts under `~/.apm2/private/fac`.
    Gc(fac_gc::GcArgs),
    /// Manage quarantined and denied jobs.
    Quarantine(fac_quarantine::QuarantineArgs),
    /// Verify containment of child processes within cgroup boundary.
    ///
    /// Checks that child processes (rustc, nextest, cc, etc.) share the
    /// same cgroup as the reference process. When sccache is enabled and
    /// containment fails, reports that sccache should be auto-disabled.
    Verify(VerifyArgs),
    /// Lane-scoped prewarm with receipts.
    ///
    /// Enqueues a warm job that pre-populates build caches in the lane
    /// target namespace to reduce cold-start probability for subsequent
    /// gates.
    Warm(WarmArgs),
    /// Benchmark harness: measure cold/warm gate times, disk footprint,
    /// and concurrency stability.
    ///
    /// Runs a standardized sequence: cold gates, warm, warm gates,
    /// multi-concurrent gates. Records results as artifacts and computes
    /// headline deltas (cold->warm improvement, target dir size collapse,
    /// denial rate).
    Bench(BenchArgs),
    /// Evidence bundle export/import with RFC-0028/RFC-0029 validation.
    ///
    /// Export produces a self-describing envelope + blobs for a job.
    /// Import validates RFC-0028 channel boundary and RFC-0029 economics
    /// receipts, rejecting bundles that fail either check (fail-closed).
    Bundle(BundleArgs),
    /// Introspect FAC queue state (forensics-first UX).
    ///
    /// Shows job counts by directory, oldest pending job, and
    /// denial/quarantine reason code distributions.
    Queue(QueueArgs),
    /// Manage admitted FAC policy: show, validate, adopt, rollback.
    ///
    /// The broker maintains an admitted policy digest. Adoption is atomic
    /// with rollback support. Every operation emits a durable receipt.
    Policy(fac_policy::PolicyArgs),
    /// Manage admitted economics profile: show, adopt, rollback.
    ///
    /// The broker maintains an admitted economics profile digest. Adoption
    /// is atomic with rollback support. Every operation emits a durable
    /// receipt. Workers deny budget admissions when profile hash mismatches.
    Economics(fac_economics::EconomicsArgs),
    /// One-shot compute-host provisioning for `FESv1`.
    ///
    /// Creates the required `$APM2_HOME/private/fac/**` directory tree with
    /// correct permissions and ownership, writes a minimal default
    /// `FacPolicyV1` (safe no-secrets posture), initializes lanes, and
    /// optionally installs systemd services. Runs doctor checks and fails
    /// with actionable output if the host cannot support `FESv1`.
    ///
    /// Idempotent: safe to re-run without destroying existing state.
    Bootstrap(crate::commands::fac_bootstrap::BootstrapArgs),
    /// Show resolved FAC configuration (operator correctness tool).
    ///
    /// Aggregates policy, boundary identity, execution backend, lane
    /// configuration, admitted digests, and queue bounds from broker
    /// and filesystem state.
    Config(crate::commands::fac_config::ConfigArgs),
    /// Receipt-derived metrics: throughput, queue latency, denial/quarantine
    /// rates, GC freed bytes, and disk preflight failures (TCK-00551).
    ///
    /// Scans the receipt index and GC receipt store for the observation
    /// window and computes aggregate metrics. Supports `--json` for
    /// automation.
    Metrics(MetricsArgs),
    /// Manage FAC caches: nuke (destructive purge with receipts).
    ///
    /// Provides explicit operator-only cache deletion with hard
    /// confirmations, safety exclusions (receipts and broker keys are
    /// NEVER deleted), and audit receipts.
    Caches(crate::commands::fac_caches::CachesArgs),
}

/// Arguments for `apm2 fac metrics`.
#[derive(Debug, Args)]
pub struct MetricsArgs {
    /// Only include receipts with timestamp >= this epoch (seconds).
    ///
    /// When omitted, defaults to 24 hours ago.
    #[arg(long)]
    pub since: Option<u64>,

    /// Only include receipts with timestamp <= this epoch (seconds).
    ///
    /// When omitted, defaults to now.
    #[arg(long)]
    pub until: Option<u64>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac warm`.
#[derive(Debug, Args)]
pub struct WarmArgs {
    /// Comma-separated list of warm phases to run.
    ///
    /// Available phases: fetch, build, nextest, clippy, doc.
    /// Default: fetch,build,nextest,clippy,doc
    #[arg(long)]
    pub phases: Option<String>,

    /// Warm only the specified lane (default: worker-assigned).
    #[arg(long)]
    pub lane: Option<String>,

    /// Wait for the warm job to complete before returning.
    #[arg(long, default_value_t = false)]
    pub wait: bool,

    /// Maximum wait time in seconds (requires --wait).
    #[arg(long, default_value_t = 1200)]
    pub wait_timeout_secs: u64,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac bench`.
#[derive(Debug, Args)]
pub struct BenchArgs {
    /// Number of concurrent gate runs for stability testing.
    ///
    /// Clamped to `MAX_CONCURRENCY` (8).
    #[arg(long, default_value_t = 2)]
    pub concurrency: u8,

    /// Skip the warm phase (cold and warm gates still run).
    #[arg(long, default_value_t = false)]
    pub skip_warm: bool,

    /// Wall timeout for each gate run (seconds).
    #[arg(long, default_value_t = 600)]
    pub timeout_seconds: u64,

    /// Memory ceiling for each gate run.
    #[arg(long, default_value = "48G")]
    pub memory_max: String,

    /// PID/task ceiling for each gate run.
    #[arg(long, default_value_t = 1536)]
    pub pids_max: u64,

    /// CPU quota for each gate run.
    #[arg(long, default_value = "200%")]
    pub cpu_quota: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac gates`.
#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct GatesArgs {
    /// Force re-run all gates, ignoring cache.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Run quick inner-loop gates (skips the heavyweight test gate).
    ///
    /// Quick mode accepts a dirty working tree for development loops and
    /// skips gate cache read/write.
    ///
    /// Use this during active implementation; run full gates before push.
    #[arg(long, default_value_t = false)]
    pub quick: bool,

    /// Wall timeout for bounded test execution (seconds).
    #[arg(long, default_value_t = 600)]
    pub timeout_seconds: u64,

    /// Memory ceiling for bounded test execution.
    #[arg(long, default_value = "48G")]
    pub memory_max: String,

    /// PID/task ceiling for bounded test execution.
    #[arg(long, default_value_t = 1536)]
    pub pids_max: u64,

    /// Throughput profile for bounded gate execution.
    #[arg(long, value_enum, default_value_t = fac_review::GateThroughputProfile::Throughput)]
    pub gate_profile: fac_review::GateThroughputProfile,

    /// CPU quota for bounded test execution (`auto` resolves from
    /// --gate-profile).
    #[arg(long, default_value = "auto")]
    pub cpu_quota: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Wait for queued gates job completion (default).
    ///
    /// While waiting, `apm2 fac gates` reports queue state so operators can
    /// see whether the job is pending or already claimed by a worker.
    #[arg(long, default_value_t = true)]
    pub wait: bool,

    /// Disable wait mode and return immediately after enqueue.
    #[arg(long, default_value_t = false, conflicts_with = "wait")]
    pub no_wait: bool,

    /// Maximum wait time in seconds when wait mode is enabled.
    #[arg(long, default_value_t = 1200)]
    pub wait_timeout_secs: u64,
}

/// Arguments for `apm2 fac preflight`.
#[derive(Debug, Args)]
pub struct PreflightArgs {
    #[command(subcommand)]
    pub subcommand: PreflightSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum PreflightSubcommand {
    /// Credential posture checks (`runtime` or `lint`).
    Credential(PreflightCredentialArgs),
    /// Workflow trust-policy authorization check.
    Authorization(PreflightAuthorizationArgs),
}

#[derive(Debug, Args)]
pub struct PreflightCredentialArgs {
    /// Credential preflight mode.
    #[arg(value_enum)]
    pub mode: fac_preflight::CredentialMode,

    /// Optional paths to scan for lint mode.
    ///
    /// Ignored in `runtime` mode.
    #[arg(value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PreflightAuthorizationArgs {
    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac work`.
#[derive(Debug, Args)]
pub struct WorkArgs {
    #[command(subcommand)]
    pub subcommand: WorkSubcommand,
}

/// Arguments for `apm2 fac doctor`.
#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct DoctorArgs {
    /// Target pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Restrict global doctor output to one repository (`owner/repo`).
    #[arg(
        long,
        value_name = "OWNER/REPO",
        conflicts_with = "pr",
        value_parser = parse_owner_repo_filter
    )]
    pub repo: Option<String>,

    /// Execute doctor-prescribed recovery actions.
    #[arg(long, default_value_t = false)]
    pub fix: bool,

    /// Output in JSON format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Upgrade credential checks from WARN to ERROR.
    ///
    /// Use this when running GitHub-facing workflows (push, review run)
    /// that require valid credentials. Without this flag, missing credentials
    /// produce WARN; with it, they produce ERROR and cause a non-zero exit.
    #[arg(long, default_value_t = false)]
    pub full: bool,

    /// Include tracked PR summaries in system doctor output.
    ///
    /// By default, `apm2 fac doctor` focuses on host readiness checks only.
    /// Use this flag (or `--full`) when tracked PR details are required.
    #[arg(long, default_value_t = false)]
    pub tracked_prs: bool,

    /// Wait until doctor recommends an action other than `wait`.
    #[arg(long, visible_alias = "wait", default_value_t = false)]
    pub wait_for_recommended_action: bool,

    /// Poll cadence while waiting for recommended action.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=10))]
    pub poll_interval_seconds: u64,

    /// Maximum wait time while waiting for recommended action.
    #[arg(
        long,
        visible_alias = "wait-timeout-secs",
        default_value_t = 1200,
        value_parser = parse_wait_timeout
    )]
    pub wait_timeout_seconds: u64,

    /// Exit only when doctor returns one of these actions (comma-separated).
    #[arg(long, value_delimiter = ',', value_enum)]
    pub exit_on: Vec<DoctorExitActionArg>,

    /// Print FAC review/lifecycle machine contracts as JSON and exit.
    #[arg(long, default_value_t = false)]
    pub machine_spec: bool,
}

/// Arguments for `apm2 fac install`.
#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Allow partial success when some service restarts fail.
    ///
    /// By default, `apm2 fac install` treats restart failure of any
    /// required service (apm2-daemon.service, apm2-worker.service) as
    /// a command failure (non-zero exit). This flag overrides that
    /// behavior: the command exits 0 even when some restarts fail,
    /// though `success` in the JSON output remains `false` when any
    /// restart failed.
    #[arg(long, default_value_t = false)]
    pub allow_partial: bool,

    /// Explicit workspace root path for the cargo install source.
    ///
    /// When set, uses this path as the trusted workspace root instead
    /// of discovering it from the running executable. Refuses ambiguous
    /// cwd-based discovery.
    #[arg(long)]
    pub workspace_root: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DoctorExitActionArg {
    Fix,
    Escalate,
    Merge,
    Done,
    Approve,
    DispatchImplementor,
    RestartReviews,
}

impl DoctorExitActionArg {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fix => "fix",
            Self::Escalate => "escalate",
            Self::Merge => "merge",
            Self::Done => "done",
            Self::Approve => "approve",
            Self::DispatchImplementor => "dispatch_implementor",
            Self::RestartReviews => "restart_reviews",
        }
    }
}

fn parse_wait_timeout(raw: &str) -> Result<u64, String> {
    let value = raw
        .parse::<u64>()
        .map_err(|err| format!("invalid timeout value `{raw}`: {err}"))?;
    if !(5..=1200).contains(&value) {
        return Err(
            "wait timeout must be between 5 and 1200 seconds (20 minutes max). If nothing has happened for 20 minutes, the orchestrator should diagnose the problem rather than wait longer."
                .to_string(),
        );
    }
    Ok(value)
}

fn parse_owner_repo_filter(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("repository filter cannot be empty".to_string());
    }

    let (owner, repo) = value
        .split_once('/')
        .ok_or_else(|| format!("invalid repository format `{value}` (expected owner/repo)"))?;

    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err(format!(
            "invalid repository format `{value}` (expected owner/repo)"
        ));
    }
    if owner == "." || owner == ".." || repo == "." || repo == ".." {
        return Err(format!(
            "invalid repository format `{value}` (reserved path segment)"
        ));
    }
    if !owner
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        || !repo
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!(
            "invalid repository format `{value}` (expected owner/repo)"
        ));
    }

    Ok(format!("{owner}/{repo}"))
}

/// Arguments for `apm2 fac services`.
#[derive(Debug, Args)]
pub struct ServicesArgs {
    /// services status
    #[command(subcommand)]
    pub subcommand: ServicesSubcommand,
}

/// Arguments for `apm2 fac services status`.
#[derive(Debug, Subcommand)]
pub enum ServicesSubcommand {
    /// Report daemon and worker managed service health.
    Status(ServicesStatusArgs),
}

#[derive(Debug, Args)]
pub struct ServicesStatusArgs {
    /// Output in JSON format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Work subcommands.
#[derive(Debug, Subcommand)]
pub enum WorkSubcommand {
    /// Show projection-backed work status from daemon authority.
    Status(WorkStatusArgs),

    /// List projection-known work items from daemon authority.
    List(WorkListArgs),
}

/// Arguments for `apm2 fac work status`.
#[derive(Debug, Args)]
pub struct WorkStatusArgs {
    /// Work identifier to query.
    pub work_id: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac work list`.
#[derive(Debug, Args)]
pub struct WorkListArgs {
    /// Return only claimable work items.
    #[arg(long, default_value_t = false)]
    pub claimable_only: bool,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac episode`.
#[derive(Debug, Args)]
pub struct EpisodeArgs {
    #[command(subcommand)]
    pub subcommand: EpisodeSubcommand,
}

/// Episode subcommands.
#[derive(Debug, Subcommand)]
pub enum EpisodeSubcommand {
    /// Inspect episode details and tool log index.
    Inspect(EpisodeInspectArgs),
}

/// Arguments for `apm2 fac episode inspect`.
#[derive(Debug, Args)]
pub struct EpisodeInspectArgs {
    /// Episode identifier to inspect.
    pub episode_id: String,

    /// Show full tool log index (default: summary only).
    #[arg(long)]
    pub full: bool,

    /// Maximum number of events to scan from the end of the ledger.
    #[arg(long, default_value_t = DEFAULT_SCAN_LIMIT)]
    pub limit: u64,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac receipts`.
#[derive(Debug, Args)]
pub struct ReceiptArgs {
    #[command(subcommand)]
    pub subcommand: ReceiptSubcommand,
}

/// Receipt subcommands.
#[derive(Debug, Subcommand)]
pub enum ReceiptSubcommand {
    /// Show receipt from CAS by content hash.
    Show(ReceiptShowArgs),
    /// List receipt headers from the index (no directory scan).
    ///
    /// Displays receipt headers sorted by timestamp (most recent first).
    /// Uses the receipt index for O(1) access. If the index is missing
    /// or corrupt, it is rebuilt automatically.
    List(ReceiptListArgs),
    /// Look up the latest receipt for a job ID.
    ///
    /// Consults the receipt index first for O(1) lookup, falling back
    /// to bounded directory scan only if the index does not contain the
    /// job. This avoids full receipt directory scans for common operations.
    Status(ReceiptStatusArgs),
    /// Rebuild the receipt index from the receipt store.
    ///
    /// Forces a full scan of all receipt files and rebuilds the
    /// non-authoritative index used for fast job/receipt lookup.
    /// The index is a cache — this command is safe to run at any time.
    Reindex(ReceiptReindexArgs),
    /// Verify a receipt's signed envelope (TCK-00576).
    ///
    /// Loads the signed receipt envelope for the given content hash and
    /// verifies the Ed25519 signature against the persistent broker key.
    /// Exits with 0 on success, non-zero on verification failure.
    Verify(ReceiptVerifyArgs),
    /// Merge receipts from one directory into another (TCK-00543).
    ///
    /// Performs set-union merge on receipt digests: copies receipts from
    /// the source directory into the target directory only if they do not
    /// already exist there. Emits an audit report with duplicates, parse
    /// failures, and `job_id` mismatches.
    Merge(ReceiptMergeArgs),
}

/// Arguments for `apm2 fac receipts show`.
#[derive(Debug, Args)]
pub struct ReceiptShowArgs {
    /// Receipt hash (hex-encoded BLAKE3).
    pub receipt_hash: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac receipts list`.
#[derive(Debug, Args)]
pub struct ReceiptListArgs {
    /// Maximum number of entries to display.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    /// Only show receipts with timestamp >= this epoch (seconds).
    ///
    /// Filters the receipt list to show only receipts created at or after
    /// the given Unix epoch timestamp. Deterministic ordering: receipts
    /// are sorted by timestamp descending, then by content hash ascending
    /// for equal timestamps.
    #[arg(long)]
    pub since: Option<u64>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac receipts status`.
#[derive(Debug, Args)]
pub struct ReceiptStatusArgs {
    /// Job ID to look up.
    pub job_id: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac receipts reindex`.
#[derive(Debug, Args)]
pub struct ReceiptReindexArgs {
    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac receipts verify` (TCK-00576).
#[derive(Debug, Args)]
pub struct ReceiptVerifyArgs {
    /// Receipt content hash (BLAKE3 hex, with or without `b3-256:` prefix)
    /// or path to a `.sig.json` signed envelope file.
    pub digest_or_path: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac receipts merge` (TCK-00543).
#[derive(Debug, Args)]
pub struct ReceiptMergeArgs {
    /// Source receipt directory to merge from.
    #[arg(long)]
    pub from: std::path::PathBuf,

    /// Target receipt directory to merge into.
    #[arg(long)]
    pub into: std::path::PathBuf,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac context`.
#[derive(Debug, Args)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub subcommand: ContextSubcommand,
}

/// Context subcommands.
#[derive(Debug, Subcommand)]
pub enum ContextSubcommand {
    /// Rebuild role-scoped context deterministically.
    Rebuild(ContextRebuildArgs),
}

/// Arguments for `apm2 fac context rebuild`.
#[derive(Debug, Args)]
pub struct ContextRebuildArgs {
    /// Role for context rebuild (implementer, reviewer, etc.).
    pub role: String,

    /// Episode identifier.
    pub episode_id: String,

    /// Output directory for rebuilt context.
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// Maximum number of events to scan from the end of the ledger.
    #[arg(long, default_value_t = DEFAULT_SCAN_LIMIT)]
    pub limit: u64,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac lane`.
#[derive(Debug, Args)]
pub struct LaneArgs {
    #[command(subcommand)]
    pub subcommand: LaneSubcommand,
}

/// Lane subcommands.
#[derive(Debug, Subcommand)]
pub enum LaneSubcommand {
    /// Show status of all FAC execution lanes.
    ///
    /// Reports each lane's state derived from lock state, lease records,
    /// and PID liveness checks. Detects stale leases from crashed jobs.
    Status(LaneStatusArgs),
    /// Initialize the lane pool: create directories and write default profiles.
    ///
    /// Bootstraps a fresh `$APM2_HOME` into a ready lane pool with one
    /// command. Existing profiles are left untouched (idempotent).
    /// Lane count is configurable via `$APM2_FAC_LANE_COUNT` (default: 3,
    /// max: 32).
    Init(LaneInitArgs),
    /// Mark a lane as CORRUPT with an operator-provided reason.
    ///
    /// Writes a `corrupt.v1.json` marker file into the lane directory.
    /// A CORRUPT lane refuses all future job leases until an operator
    /// clears the marker via `apm2 fac doctor --fix`.
    ///
    /// This is an operator tool for manually quarantining a lane when
    /// automated detection has not yet triggered (e.g., suspected data
    /// corruption, external incident, or proactive maintenance).
    MarkCorrupt(LaneMarkCorruptArgs),
}

/// Arguments for `apm2 fac lane status`.
#[derive(Debug, Args)]
pub struct LaneStatusArgs {
    /// Show only lanes matching this state (IDLE, RUNNING, LEASED, CLEANUP,
    /// CORRUPT).
    #[arg(long)]
    pub state: Option<String>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac lane init` (TCK-00539).
#[derive(Debug, Args)]
pub struct LaneInitArgs {
    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac lane mark-corrupt` (TCK-00570).
#[derive(Debug, Args)]
pub struct LaneMarkCorruptArgs {
    /// Lane identifier to mark as corrupt (e.g., `lane-00`).
    pub lane_id: String,

    /// Human-readable reason for marking the lane as corrupt.
    #[arg(long)]
    pub reason: String,

    /// Optional cleanup receipt digest (`b3-256:<hex>`) to bind this
    /// marker to an evidence artifact.
    #[arg(long)]
    pub receipt_digest: Option<String>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac worker`.
#[derive(Debug, Args)]
pub struct WorkerArgs {
    /// Process exactly one job and exit.
    #[arg(long, default_value_t = false)]
    pub once: bool,

    /// Seconds between queue scans in continuous mode.
    #[arg(long, default_value_t = 5)]
    pub poll_interval_secs: u64,

    /// Maximum total jobs to process before exiting (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    pub max_jobs: u64,

    /// Print computed systemd unit properties for each selected job.
    #[arg(long, default_value_t = false)]
    pub print_unit: bool,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac job`.
#[derive(Debug, Args)]
pub struct JobArgs {
    #[command(subcommand)]
    pub subcommand: JobSubcommand,
}

/// Job lifecycle subcommands.
#[derive(Debug, Subcommand)]
pub enum JobSubcommand {
    /// Cancel a pending, claimed, or running job.
    ///
    /// If the job is pending: atomically moves it to `cancelled/` and emits a
    /// cancellation receipt.
    ///
    /// If the job is claimed or running: enqueues a highest-priority
    /// `stop_revoke` job that kills the active systemd unit
    /// (`KillMode=control-group`) and moves the target job to `cancelled/`.
    ///
    /// Cancellation never deletes evidence or logs; it only stops execution
    /// and writes receipts.
    Cancel(CancelArgs),

    /// Show detailed information about a job.
    ///
    /// Displays the job spec, latest receipt, current queue directory state,
    /// and pointers to related log files. Supports `--json` for machine-
    /// readable output.
    Show(JobShowArgs),
}

/// Arguments for `apm2 fac job show`.
#[derive(Debug, Args)]
pub struct JobShowArgs {
    /// The job ID to inspect.
    pub job_id: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac job cancel`.
#[derive(Debug, Args)]
pub struct CancelArgs {
    /// The job ID to cancel.
    pub job_id: String,

    /// Reason for cancellation (recorded in receipt).
    #[arg(long, default_value = "operator-initiated cancellation")]
    pub reason: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac queue`.
#[derive(Debug, Args)]
pub struct QueueArgs {
    #[command(subcommand)]
    pub subcommand: QueueSubcommand,
}

/// Queue introspection subcommands.
#[derive(Debug, Subcommand)]
pub enum QueueSubcommand {
    /// Show queue status: counts by directory, oldest jobs, denial/quarantine
    /// stats.
    ///
    /// Scans queue directories with bounded reads and reports per-directory
    /// job counts, the oldest job in each directory, and denial/quarantine
    /// reason code distributions.
    Status(QueueStatusArgs),
}

/// Arguments for `apm2 fac queue status`.
#[derive(Debug, Args)]
pub struct QueueStatusArgs {
    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[command(subcommand)]
    pub subcommand: VerifySubcommand,
}

/// Verify subcommands.
#[derive(Debug, Subcommand)]
pub enum VerifySubcommand {
    /// Verify cgroup containment of child processes.
    ///
    /// Checks that child processes (rustc, nextest, cc, ld, sccache)
    /// share the same cgroup hierarchy as the reference process. When
    /// sccache is enabled and containment fails, reports that sccache
    /// should be auto-disabled.
    Containment(ContainmentArgs),
}

/// Arguments for `apm2 fac verify containment`.
#[derive(Debug, Args)]
pub struct ContainmentArgs {
    /// PID of the reference process (job unit main process).
    ///
    /// All child processes will be checked against this PID's cgroup.
    /// If not specified, uses the current process PID.
    #[arg(long)]
    pub pid: Option<u32>,

    /// Whether sccache is currently enabled for the build.
    ///
    /// When true and containment fails, the verdict reports that
    /// sccache should be auto-disabled.
    #[arg(long, default_value_t = false)]
    pub sccache_enabled: bool,

    /// Output in JSON format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac bundle`.
#[derive(Debug, Args)]
pub struct BundleArgs {
    #[command(subcommand)]
    pub subcommand: BundleSubcommand,
}

/// Bundle subcommands.
#[derive(Debug, Subcommand)]
pub enum BundleSubcommand {
    /// Export an evidence bundle for a job.
    ///
    /// Produces a self-describing envelope JSON + referenced blobs under
    /// an export directory. The envelope includes RFC-0028 boundary check
    /// data and RFC-0029 economics traces from the job receipt.
    Export(BundleExportArgs),
    /// Import an evidence bundle from a path.
    ///
    /// Validates RFC-0028 channel boundary (must pass with zero defects)
    /// and RFC-0029 economics receipts (must be Allow verdicts). Rejects
    /// bundles that fail either validation (fail-closed).
    Import(BundleImportArgs),
}

/// Arguments for `apm2 fac bundle export`.
#[derive(Debug, Args)]
pub struct BundleExportArgs {
    /// Job ID to export the evidence bundle for.
    pub job_id: String,

    /// Output directory for the exported bundle.
    ///
    /// Defaults to `$APM2_HOME/private/fac/bundles/<job_id>/`.
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac bundle import`.
#[derive(Debug, Args)]
pub struct BundleImportArgs {
    /// Path to the evidence bundle manifest JSON file.
    pub path: PathBuf,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac push`.
#[derive(Debug, Args)]
pub struct PushArgs {
    /// Git remote name.
    #[arg(long, default_value = "origin")]
    pub remote: String,

    /// Git branch to push. Defaults to current branch.
    #[arg(long)]
    pub branch: Option<String>,

    /// Optional ticket YAML path for consistency checking against derived TCK
    /// id.
    #[arg(long)]
    pub ticket: Option<PathBuf>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac restart`.
#[derive(Debug, Args)]
pub struct RestartArgs {
    /// Pull request number (auto-detected from current branch if omitted).
    #[arg(long)]
    pub pr: Option<u32>,

    /// Restart everything regardless of current CI state.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Refresh local projection identity from authoritative PR head before
    /// restart strategy resolution.
    #[arg(long, default_value_t = false)]
    pub refresh_identity: bool,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac recover`.
#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct RecoverArgs {
    /// Pull request number (auto-detected from local branch if omitted).
    #[arg(long)]
    pub pr: Option<u32>,

    /// Force lifecycle recovery from the current local SHA.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Refresh local projection identity from current authoritative PR head.
    #[arg(long, default_value_t = false)]
    pub refresh_identity: bool,

    /// Reap stale/dead agent entries for the target PR.
    #[arg(long, default_value_t = false)]
    pub reap_stale_agents: bool,

    /// Reset local lifecycle state for the target PR.
    #[arg(long, default_value_t = false)]
    pub reset_lifecycle: bool,

    /// Run all recovery operations for the target PR.
    #[arg(long, default_value_t = false)]
    pub all: bool,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac logs`.
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Filter logs to a specific pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Selector type for digest-first zoom-in (`finding` or `tool_output`).
    #[arg(long)]
    pub selector_type: Option<String>,

    /// Selector token to resolve.
    ///
    /// `finding` selectors:
    /// `finding:v2:<owner/repo>:<pr>:<sha>:<dimension>:<finding_id>`
    /// `tool_output` selectors: `tool_output:v1:<sha>:<gate>`
    #[arg(long)]
    pub selector: Option<String>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac pipeline` (hidden, internal).
#[derive(Debug, Args)]
pub struct PipelineArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: u32,

    /// Commit SHA to run pipeline against.
    #[arg(long)]
    pub sha: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac review`.
#[derive(Debug, Args)]
pub struct ReviewArgs {
    #[command(subcommand)]
    pub subcommand: ReviewSubcommand,
}

/// Review subcommands.
#[derive(Debug, Subcommand)]
pub enum ReviewSubcommand {
    /// Run FAC review orchestration for a pull request URL.
    Run(ReviewRunArgs),
    /// Materialize local review inputs (diff + commit history) under FAC
    /// private storage.
    Prepare(ReviewPrepareArgs),
    /// Append one structured SHA-bound finding to local FAC findings.
    Finding(ReviewFindingArgs),
    /// Compatibility shim for deprecated `review comment` (maps to finding).
    #[command(hide = true)]
    Comment(ReviewCommentArgs),
    /// Retrieve structured SHA-bound review findings for a PR head SHA.
    Findings(ReviewFindingsArgs),
    /// Show or set explicit verdict state per review dimension.
    Verdict(ReviewVerdictArgs),
    /// Tail FAC review NDJSON event stream.
    Tail(ReviewTailArgs),
    /// Terminate a running reviewer process for a specific PR and type.
    Terminate(ReviewTerminateArgs),
}

/// Arguments for `apm2 fac review run`.
#[derive(Debug, Args)]
pub struct ReviewRunArgs {
    /// Pull request number (auto-detected from local branch if omitted).
    #[arg(long)]
    pub pr: Option<u32>,

    /// Review selection (`all`, `security`, or `quality`).
    #[arg(
        long = "type",
        alias = "review-type",
        value_enum,
        default_value_t = fac_review::ReviewRunType::All
    )]
    pub review_type: fac_review::ReviewRunType,

    /// Optional expected head SHA (40 hex) to fail closed on stale review
    /// start.
    #[arg(long)]
    pub expected_head_sha: Option<String>,

    /// Force re-running on the same SHA even when a terminal run already
    /// exists for this review type.
    ///
    /// This does not bypass merge-conflict checks against `main`.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Review lane filter for `apm2 fac review terminate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ReviewStatusTypeArg {
    Security,
    Quality,
}

impl ReviewStatusTypeArg {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Quality => "quality",
        }
    }
}

/// Arguments for `apm2 fac review findings`.
#[derive(Debug, Args)]
pub struct ReviewFindingsArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Optional head SHA override (defaults to PR head SHA).
    #[arg(long)]
    pub sha: Option<String>,

    /// Deprecated compatibility flag; ignored because findings are local-only.
    #[arg(long, default_value_t = false, hide = true)]
    pub refresh: bool,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac review prepare`.
#[derive(Debug, Args)]
pub struct ReviewPrepareArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Optional head SHA override (defaults to PR head SHA).
    #[arg(long)]
    pub sha: Option<String>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac review finding`.
#[derive(Debug, Args)]
pub struct ReviewFindingArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Optional head SHA override (defaults to local PR identity SHA).
    #[arg(long)]
    pub sha: Option<String>,

    /// Review dimension (`security` or `code-quality`).
    #[arg(long = "type", value_enum)]
    pub review_type: fac_review::ReviewFindingTypeArg,

    /// Finding severity (`blocker`, `major`, `minor`, `nit`).
    #[arg(long, value_enum)]
    pub severity: fac_review::ReviewFindingSeverityArg,

    /// Short finding summary.
    #[arg(long)]
    pub summary: String,

    /// Optional detailed remediation body (alias: --body).
    #[arg(long = "details", alias = "body")]
    pub details: Option<String>,

    /// Optional risk statement.
    #[arg(long)]
    pub risk: Option<String>,

    /// Optional impact statement.
    #[arg(long)]
    pub impact: Option<String>,

    /// Optional location hint (`path:line` or symbol name).
    #[arg(long)]
    pub location: Option<String>,

    /// Optional reviewer identity tag.
    #[arg(long)]
    pub reviewer_id: Option<String>,

    /// Optional model identifier that produced the finding.
    #[arg(long)]
    pub model_id: Option<String>,

    /// Optional backend identifier that produced the finding.
    #[arg(long)]
    pub backend_id: Option<String>,

    /// Optional evidence pointer (selector or local path hint).
    #[arg(long)]
    pub evidence_pointer: Option<String>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for deprecated `apm2 fac review comment` compatibility shim.
#[derive(Debug, Args)]
pub struct ReviewCommentArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Optional head SHA override (defaults to local PR identity SHA).
    #[arg(long)]
    pub sha: Option<String>,

    /// Review dimension (`security` or `code-quality`).
    #[arg(long = "type", value_enum)]
    pub review_type: fac_review::ReviewCommentTypeArg,

    /// Finding severity (`blocker`, `major`, `minor`, `nit`).
    #[arg(long, value_enum)]
    pub severity: fac_review::ReviewCommentSeverityArg,

    /// Finding body text (when omitted, read from stdin).
    #[arg(long)]
    pub body: Option<String>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac review verdict`.
#[derive(Debug, Args)]
pub struct ReviewVerdictArgs {
    #[command(subcommand)]
    pub subcommand: ReviewVerdictSubcommand,
}

/// Subcommands for `apm2 fac review verdict`.
#[derive(Debug, Subcommand)]
pub enum ReviewVerdictSubcommand {
    /// Show SHA-bound verdict state for all active review dimensions.
    Show(ReviewVerdictShowArgs),
    /// Set SHA-bound verdict for one review dimension.
    Set(ReviewVerdictSetArgs),
}

/// Arguments for `apm2 fac review verdict show`.
#[derive(Debug, Args)]
pub struct ReviewVerdictShowArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Optional head SHA override (defaults to PR head SHA).
    #[arg(long)]
    pub sha: Option<String>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac review verdict set`.
#[derive(Debug, Args)]
pub struct ReviewVerdictSetArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Optional head SHA override (defaults to PR head SHA).
    #[arg(long)]
    pub sha: Option<String>,

    /// Verdict dimension (`security` or `code-quality`).
    #[arg(long)]
    pub dimension: String,

    /// Verdict value (`approve` or `deny`).
    #[arg(long, value_enum)]
    pub verdict: fac_review::VerdictValueArg,

    /// Optional free-form reason attached to this verdict.
    #[arg(long)]
    pub reason: Option<String>,

    /// Optional model identifier that produced this verdict.
    #[arg(long)]
    pub model_id: Option<String>,

    /// Optional backend identifier that produced this verdict.
    #[arg(long)]
    pub backend_id: Option<String>,

    /// Keep prepared review input files under FAC private storage after verdict
    /// is written.
    #[arg(long, default_value_t = false)]
    pub keep_prepared_inputs: bool,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac review tail`.
#[derive(Debug, Args)]
pub struct ReviewTailArgs {
    /// Number of lines to show from the end of the event stream.
    #[arg(long, default_value_t = 20)]
    pub lines: usize,

    /// Follow mode (stream appended events).
    #[arg(long, default_value_t = false)]
    pub follow: bool,

    /// Emit JSON output for this command (no-op; output is already NDJSON).
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac review terminate`.
#[derive(Debug, Args)]
pub struct ReviewTerminateArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Reviewer type to terminate (security or quality).
    #[arg(long = "type", value_enum)]
    pub review_type: ReviewStatusTypeArg,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

// =============================================================================
// Response Types
// =============================================================================

/// Response for work status command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkStatusResponse {
    /// Work identifier.
    pub work_id: String,
    /// Current work status inferred from ledger.
    pub status: String,
    /// Actor who claimed this work (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    /// Role of the actor (if claimed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Latest episode ID associated with this work.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_episode_id: Option<String>,
    /// Latest receipt hash (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_receipt_hash: Option<String>,
    /// Number of events found for this work.
    pub event_count: u64,
    /// Ledger sequence ID of the latest event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_seq_id: Option<u64>,
}

/// Response for episode inspect command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeInspectResponse {
    /// Episode identifier.
    pub episode_id: String,
    /// Episode status inferred from ledger.
    pub status: String,
    /// Associated work ID (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_id: Option<String>,
    /// Actor ID (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    /// Role (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Tool log index summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_log_summary: Option<ToolLogSummary>,
    /// Full tool log index (if --full flag).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_log_index: Option<ToolLogIndexV1>,
    /// Number of events found for this episode.
    pub event_count: u64,
}

/// Summary of tool log index.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLogSummary {
    /// Total tool executions.
    pub total_executions: u64,
    /// Successful executions.
    pub successful_executions: u64,
    /// Failed executions.
    pub failed_executions: u64,
    /// Total tokens consumed.
    pub total_tokens: u64,
    /// Total I/O bytes.
    pub total_bytes_io: u64,
    /// Total wall time in milliseconds.
    pub total_wall_ms: u64,
}

/// Response for receipt show command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptShowResponse {
    /// Receipt hash (hex-encoded).
    pub hash: String,
    /// Receipt type (`gate_receipt`, `review_receipt`, `summary_receipt`,
    /// etc.).
    pub receipt_type: String,
    /// Receipt size in bytes.
    pub size_bytes: u64,
    /// Receipt content (JSON parsed if possible).
    pub content: serde_json::Value,
}

/// Response for context rebuild command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRebuildResponse {
    /// Role used for rebuild.
    pub role: String,
    /// Episode ID.
    pub episode_id: String,
    /// Output directory path.
    pub output_dir: String,
    /// Context pack hash (hex-encoded).
    pub context_pack_hash: String,
    /// Number of artifacts retrieved from CAS.
    pub artifacts_retrieved: u64,
    /// Whether rebuild was deterministic (matched expected hash).
    pub deterministic: bool,
}

/// Error response for JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    /// Stable machine-readable error code.
    pub error: String,
    /// Error message.
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceStatusResponse {
    /// Unit name.
    pub unit: String,
    /// Scope used for query.
    pub scope: String,
    /// Unit load state.
    pub load_state: String,
    /// Unit active state.
    pub active_state: String,
    /// Unit sub-state.
    pub sub_state: String,
    /// Whether unit is enabled in unit files.
    pub enabled: String,
    /// Main PID from systemd.
    pub main_pid: u32,
    /// Unit uptime in seconds.
    pub uptime_seconds: u64,
    /// Watchdog timeout in seconds (0 if not configured).
    pub watchdog_sec: u64,
    /// Deterministic health verdict: "healthy", "degraded", or "unhealthy".
    pub health: String,
    /// Error encountered while checking the unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrphanedSystemdUnitDiagnostic {
    /// Lane whose stale lease has orphaned systemd evidence.
    pub lane_id: String,
    /// Job bound to the stale lease.
    pub job_id: String,
    /// Lease PID observed as dead/reused.
    pub pid: u32,
    /// Stable machine-readable reason code.
    pub reason_code: String,
    /// Liveness verdict for associated units ("active" or "unknown").
    pub liveness: String,
    /// Human-readable detail for operators.
    pub detail: String,
    /// Remediation guidance for operators.
    pub recommended_action: String,
    /// Active associated unit names (if known).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_units: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServicesStatusResponse {
    /// Overall health: "healthy" if all services are healthy, "degraded"
    /// otherwise.
    pub overall_health: String,
    /// List of managed services.
    pub services: Vec<ServiceStatusResponse>,
    /// Worker heartbeat status (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_heartbeat: Option<apm2_core::fac::worker_heartbeat::HeartbeatStatus>,
    /// Broker health IPC status (if available).
    ///
    /// TCK-00600: Exposes broker version, readiness, and health independently
    /// of systemd unit state. This is the source of truth for whether the
    /// daemon's internal health checks are passing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_health: Option<apm2_core::fac::broker_health_ipc::BrokerHealthIpcStatus>,
    /// Stale-lease reclaim blockers caused by orphaned systemd units.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphaned_systemd_units: Vec<OrphanedSystemdUnitDiagnostic>,
    /// Probe error for orphaned-systemd-unit diagnostics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphaned_systemd_unit_error: Option<String>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SystemDoctorFixActionStatus {
    Applied,
    Skipped,
    Blocked,
    Failed,
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum SystemDoctorFixActionKind {
    LaneReconcile,
    QueueReconcileApply,
    LaneLogGc,
    LaneStatusScan,
    LaneTmpCorruptionDetection,
    LaneTmpCorruptionDetected,
    LaneTmpScrub,
    LaneResetOrphanedSystemdUnit,
    LaneResetTmpCorruption,
    LaneResetCleanupRecovery,
    QueueReconcilePostLaneReset,
    WorkerRestart,
    DoctorPostCheck,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SystemDoctorFixAction {
    pub action: SystemDoctorFixActionKind,
    pub status: SystemDoctorFixActionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SystemDoctorFixResponse {
    pub schema: String,
    pub actions: Vec<SystemDoctorFixAction>,
    pub checks_before: Vec<crate::commands::daemon::DaemonDoctorCheck>,
    pub checks_after: Vec<crate::commands::daemon::DaemonDoctorCheck>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tracked_prs: Vec<fac_review::DoctorTrackedPrSummary>,
    pub had_errors_before: bool,
    pub has_errors_after: bool,
}

#[derive(Debug)]
struct DoctorSystemSnapshot {
    checks: Vec<crate::commands::daemon::DaemonDoctorCheck>,
    tracked_prs: Vec<fac_review::DoctorTrackedPrSummary>,
    has_critical_error: bool,
}

#[derive(Debug)]
enum DoctorLaneResetError {
    Running { pid: Option<u32> },
    RefusedDelete { receipts: Vec<RefusedDeleteReceipt> },
    Other(String),
}

#[derive(Debug, Clone, Copy)]
struct DoctorLaneResetSummary {
    files_deleted: u64,
    dirs_deleted: u64,
}

#[derive(Debug, Clone, Copy)]
struct TmpScrubSummary {
    entries_deleted: u64,
}

#[derive(Debug, Clone, Copy)]
struct LaneLogGcSummary {
    targets: usize,
    actions_applied: usize,
    errors: usize,
    bytes_freed: u64,
}

#[derive(Debug, Clone, Copy)]
enum ServiceScope {
    /// User systemd scope.
    User,
    /// System systemd scope.
    System,
}

impl ServiceScope {
    const fn scope_flag(self) -> Option<&'static str> {
        match self {
            Self::User => Some("--user"),
            Self::System => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
        }
    }
}

const SERVICE_SCOPES: [ServiceScope; 2] = [ServiceScope::User, ServiceScope::System];

fn describe_orphaned_unit_liveness(liveness: FacUnitLiveness) -> (String, String, Vec<String>) {
    match liveness {
        FacUnitLiveness::Active { active_units } => {
            let preview = active_units
                .iter()
                .take(4)
                .map(std::string::String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let detail = if preview.is_empty() {
                format!(
                    "associated systemd units still active (count={})",
                    active_units.len()
                )
            } else {
                let suffix = if active_units.len() > 4 { " +more" } else { "" };
                format!(
                    "associated systemd units still active (count={}, units=[{preview}]{suffix})",
                    active_units.len()
                )
            };
            ("active".to_string(), detail, active_units)
        },
        FacUnitLiveness::Unknown { reason } => (
            "unknown".to_string(),
            format!("systemd liveness probe inconclusive ({reason}); fail-closed"),
            Vec::new(),
        ),
        FacUnitLiveness::Inactive => (
            "inactive".to_string(),
            "no active associated systemd units".to_string(),
            Vec::new(),
        ),
    }
}

fn enforce_lane_reset_liveness_guard<F>(
    lane_id: &str,
    job_id: Option<&str>,
    probe: F,
) -> Result<(), String>
where
    F: FnOnce(&str, &str) -> FacUnitLiveness,
{
    let Some(job_id) = job_id else {
        return Err("reset blocked: cannot verify unit liveness without lease job_id".to_string());
    };
    let liveness = probe(lane_id, job_id);
    if matches!(liveness, FacUnitLiveness::Inactive) {
        return Ok(());
    }

    let (state, detail, active_units) = describe_orphaned_unit_liveness(liveness);
    if active_units.is_empty() {
        Err(format!("reset blocked while liveness={state}: {detail}"))
    } else {
        Err(format!(
            "reset blocked while liveness={state}: {detail}; active_units={}",
            active_units.join(", ")
        ))
    }
}

fn collect_orphaned_systemd_units(
    fac_root: &Path,
) -> Result<Vec<OrphanedSystemdUnitDiagnostic>, String> {
    let lane_mgr = LaneManager::new(fac_root.to_path_buf())
        .map_err(|err| format!("lane manager init failed: {err}"))?;
    let mut diagnostics = Vec::new();

    for lane_id in LaneManager::default_lane_ids() {
        let lane_dir = lane_mgr.lane_dir(&lane_id);
        let lease = LaneLeaseV1::load(&lane_dir)
            .map_err(|err| format!("failed to load lease for {lane_id}: {err}"))?;
        let Some(lease) = lease else {
            continue;
        };
        if !matches!(
            lease.state,
            LaneState::Running | LaneState::Leased | LaneState::Cleanup
        ) {
            continue;
        }
        let identity = verify_pid_identity(lease.pid, lease.proc_start_time_ticks);
        if !matches!(
            identity,
            ProcessIdentity::Dead | ProcessIdentity::AliveMismatch
        ) {
            continue;
        }

        let (liveness_state, detail, active_units) =
            describe_orphaned_unit_liveness(check_fac_unit_liveness(&lane_id, &lease.job_id));
        if liveness_state == "inactive" {
            continue;
        }
        diagnostics.push(OrphanedSystemdUnitDiagnostic {
            lane_id: lane_id.clone(),
            job_id: lease.job_id.clone(),
            pid: lease.pid,
            reason_code: ORPHANED_SYSTEMD_UNIT_REASON_CODE.to_string(),
            liveness: liveness_state,
            detail,
            recommended_action:
                "run stop_revoke for the target job to stop active units, then run `apm2 fac doctor --fix`".to_string(),
            active_units,
        });
    }

    Ok(diagnostics)
}

fn push_system_doctor_fix_action(
    actions: &mut Vec<SystemDoctorFixAction>,
    action: SystemDoctorFixActionKind,
    status: SystemDoctorFixActionStatus,
    lane_id: Option<&str>,
    detail: impl Into<String>,
) {
    actions.push(SystemDoctorFixAction {
        action,
        status,
        lane_id: lane_id.map(std::string::ToString::to_string),
        detail: detail.into(),
    });
}

const fn system_doctor_fix_exit_code(
    action_failed: bool,
    has_blocked_actions: bool,
    has_errors_after: bool,
) -> u8 {
    if action_failed || has_blocked_actions || has_errors_after {
        exit_codes::GENERIC_ERROR
    } else {
        exit_codes::SUCCESS
    }
}

fn collect_system_doctor_snapshot(
    operator_socket: &Path,
    config_path: &Path,
    full: bool,
    include_tracked_prs: bool,
    repo_filter: Option<&str>,
) -> Result<DoctorSystemSnapshot, String> {
    let (mut checks, has_critical_error) =
        crate::commands::daemon::collect_doctor_checks(operator_socket, config_path, full)
            .map_err(|err| err.to_string())?;
    let tracked_prs = if include_tracked_prs {
        match fac_review::collect_tracked_pr_summaries(repo_filter, repo_filter) {
            Ok(value) => value,
            Err(err) => {
                checks.push(crate::commands::daemon::DaemonDoctorCheck {
                    name: "tracked_pr_summary".to_string(),
                    status: "WARN",
                    message: format!("failed to build tracked PR doctor summary: {err}"),
                });
                Vec::new()
            },
        }
    } else {
        Vec::new()
    };

    Ok(DoctorSystemSnapshot {
        checks,
        tracked_prs,
        has_critical_error,
    })
}

fn emit_system_doctor_snapshot(snapshot: &DoctorSystemSnapshot) {
    let payload = serde_json::json!({
        "schema": FAC_DOCTOR_SYSTEM_SCHEMA,
        "checks": snapshot.checks,
        "tracked_prs": snapshot.tracked_prs,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
    );
}

fn load_lane_reason_hint(manager: &LaneManager, status: &LaneStatusV1) -> Option<String> {
    if let Some(reason) = status.corrupt_reason.as_ref() {
        return Some(reason.clone());
    }
    if status.state != LaneState::Corrupt {
        return None;
    }
    let lease = LaneLeaseV1::load(&manager.lane_dir(&status.lane_id))
        .ok()
        .flatten()?;
    if lease.state == LaneState::Corrupt && lease.pid == 0 {
        return Some(lease.job_id);
    }
    None
}

fn should_attempt_cleanup_scrub(reason_hint: &str) -> bool {
    let reason = reason_hint.to_ascii_lowercase();
    reason.contains("more than") && reason.contains("entries")
        || reason.contains("unexpected file type")
        || reason.contains("symlink detected")
        || reason.contains("tmp")
}

fn is_tmp_residue_name(name: &str) -> bool {
    name.starts_with(".tmp")
        || name.starts_with("tmp.")
        || Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp"))
}

fn detect_lane_tmp_corruption(
    manager: &LaneManager,
    lane_id: &str,
) -> Result<Option<String>, String> {
    let tmp_dir = manager.lane_dir(lane_id).join("tmp");
    let tmp_meta = match std::fs::symlink_metadata(&tmp_dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to stat tmp dir {}: {err}",
                tmp_dir.display()
            ));
        },
    };

    if !tmp_meta.is_dir() {
        return Ok(Some(format!(
            "tmp path is not a directory: {}",
            tmp_dir.display()
        )));
    }

    let entries = std::fs::read_dir(&tmp_dir)
        .map_err(|err| format!("failed to read tmp dir {}: {err}", tmp_dir.display()))?;
    let mut scanned_entries: usize = 0;
    for entry in entries {
        scanned_entries = scanned_entries.saturating_add(1);
        if scanned_entries > MAX_TMP_SCRUB_ENTRIES {
            return Ok(Some(format!(
                "tmp entry count exceeded bound (>{MAX_TMP_SCRUB_ENTRIES})"
            )));
        }

        let entry = entry.map_err(|err| format!("failed to read tmp entry: {err}"))?;
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!(
                    "failed to stat tmp entry {}: {err}",
                    path.display()
                ));
            },
        };
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            return Ok(Some(format!(
                "tmp contains symlink entry {}",
                path.display()
            )));
        }
        if meta.is_dir() {
            continue;
        }
        if meta.is_file() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if is_tmp_residue_name(&name) {
                return Ok(Some(format!(
                    "tmp contains transient residue entry {}",
                    path.display()
                )));
            }
            continue;
        }
        return Ok(Some(format!(
            "tmp contains unsupported file type at {}",
            path.display()
        )));
    }

    Ok(None)
}

fn doctor_reset_lane_once(
    manager: &LaneManager,
    lane_id: &str,
) -> Result<DoctorLaneResetSummary, DoctorLaneResetError> {
    manager.ensure_directories().map_err(|err| {
        DoctorLaneResetError::Other(format!("failed to ensure directories: {err}"))
    })?;

    let _lock_guard = manager
        .acquire_lock(lane_id)
        .map_err(|err| DoctorLaneResetError::Other(format!("failed to acquire lock: {err}")))?;
    let status = manager
        .lane_status(lane_id)
        .map_err(|err| DoctorLaneResetError::Other(format!("failed to load lane status: {err}")))?;
    if status.state == LaneState::Running {
        return Err(DoctorLaneResetError::Running { pid: status.pid });
    }

    let lane_dir = manager.lane_dir(lane_id);
    let Some(lanes_root) = lane_dir.parent() else {
        return Err(DoctorLaneResetError::Other(format!(
            "lane directory {} has no parent",
            lane_dir.display()
        )));
    };

    let mut subdirs: Vec<&str> = vec!["workspace", "target", "logs"];
    subdirs.extend_from_slice(LANE_ENV_DIRS);

    let mut total_files: u64 = 0;
    let mut total_dirs: u64 = 0;
    let mut refused_receipts: Vec<RefusedDeleteReceipt> = Vec::new();
    for subdir in &subdirs {
        let subdir_path = lane_dir.join(subdir);
        match safe_rmtree_v1(&subdir_path, lanes_root) {
            Ok(SafeRmtreeOutcome::Deleted {
                files_deleted,
                dirs_deleted,
            }) => {
                total_files = total_files.saturating_add(files_deleted);
                total_dirs = total_dirs.saturating_add(dirs_deleted);
            },
            Ok(SafeRmtreeOutcome::AlreadyAbsent) => {},
            Err(err) => {
                refused_receipts.push(RefusedDeleteReceipt {
                    root: subdir_path,
                    allowed_parent: lanes_root.to_path_buf(),
                    reason: err.to_string(),
                    mark_corrupt: true,
                });
            },
        }
    }
    if !refused_receipts.is_empty() {
        return Err(DoctorLaneResetError::RefusedDelete {
            receipts: refused_receipts,
        });
    }

    LaneLeaseV1::remove(&lane_dir).map_err(|err| {
        DoctorLaneResetError::Other(format!("failed to remove lane lease: {err}"))
    })?;
    LaneCorruptMarkerV1::remove(manager.fac_root(), lane_id).map_err(|err| {
        DoctorLaneResetError::Other(format!("failed to clear corrupt marker: {err}"))
    })?;

    manager.ensure_directories().map_err(|err| {
        DoctorLaneResetError::Other(format!("failed to re-create lane directories: {err}"))
    })?;

    Ok(DoctorLaneResetSummary {
        files_deleted: total_files,
        dirs_deleted: total_dirs,
    })
}

fn refused_delete_mentions_tmp(receipts: &[RefusedDeleteReceipt]) -> bool {
    receipts
        .iter()
        .any(|receipt| receipt.root.file_name().and_then(|name| name.to_str()) == Some("tmp"))
}

fn scrub_lane_tmp_dir(manager: &LaneManager, lane_id: &str) -> Result<TmpScrubSummary, String> {
    scrub_lane_tmp_dir_with_entry_limit(manager, lane_id, MAX_TMP_SCRUB_ENTRIES)
}

fn ensure_tmp_dir_exists(tmp_dir: &Path) -> Result<(), String> {
    match std::fs::create_dir(tmp_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(tmp_dir).map_err(|meta_err| {
                format!(
                    "failed to verify existing tmp path {}: {meta_err}",
                    tmp_dir.display()
                )
            })?;
            if meta.is_dir() {
                Ok(())
            } else {
                Err(format!(
                    "tmp path {} exists but is not a directory",
                    tmp_dir.display()
                ))
            }
        },
        Err(err) => Err(format!(
            "failed to create tmp directory {}: {err}",
            tmp_dir.display()
        )),
    }
}

fn scrub_lane_tmp_dir_with_entry_limit(
    manager: &LaneManager,
    lane_id: &str,
    max_entries_per_dir: usize,
) -> Result<TmpScrubSummary, String> {
    let lane_dir = manager.lane_dir(lane_id);
    let tmp_dir = lane_dir.join("tmp");
    let effective_limit = max_entries_per_dir.min(MAX_LOG_DIR_ENTRIES);

    let tmp_meta = match std::fs::symlink_metadata(&tmp_dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TmpScrubSummary { entries_deleted: 0 });
        },
        Err(err) => {
            return Err(format!(
                "failed to stat tmp dir {}: {err}",
                tmp_dir.display()
            ));
        },
    };

    if !tmp_meta.is_dir() {
        std::fs::remove_file(&tmp_dir)
            .map_err(|err| format!("failed to remove non-directory tmp path: {err}"))?;
        ensure_tmp_dir_exists(&tmp_dir)?;
        return Ok(TmpScrubSummary { entries_deleted: 1 });
    }

    // Delete the tmp tree in one bounded traversal, then recreate it.
    // This prevents per-entry nested traversals from multiplying bounds.
    let scrubbed =
        safe_rmtree_v1_with_entry_limit(&tmp_dir, &lane_dir, effective_limit).map_err(|err| {
            match err {
                SafeRmtreeError::TooManyEntries { .. } => format!(
                    "tmp scrub refused directory {} due to entry bound (> {})",
                    tmp_dir.display(),
                    effective_limit
                ),
                _ => format!("tmp scrub failed to delete {}: {err}", tmp_dir.display()),
            }
        })?;

    ensure_tmp_dir_exists(&tmp_dir)?;

    let entries_deleted = match scrubbed {
        SafeRmtreeOutcome::Deleted {
            files_deleted,
            dirs_deleted,
        } => files_deleted.saturating_add(dirs_deleted.saturating_sub(1)),
        SafeRmtreeOutcome::AlreadyAbsent => 0,
    };

    Ok(TmpScrubSummary { entries_deleted })
}

fn gc_stale_lane_logs(fac_root: &Path, manager: &LaneManager) -> Result<LaneLogGcSummary, String> {
    let gc_plan =
        plan_gc_with_log_retention(fac_root, manager, 0, 0, &LogRetentionConfig::default())
            .map_err(|err| format!("failed to build lane log GC plan: {err:?}"))?;

    let targets: Vec<_> = gc_plan
        .targets
        .into_iter()
        .filter(|target| {
            matches!(
                target.kind,
                GcActionKind::LaneLogRetention | GcActionKind::LaneLog
            )
        })
        .collect();
    if targets.is_empty() {
        return Ok(LaneLogGcSummary {
            targets: 0,
            actions_applied: 0,
            errors: 0,
            bytes_freed: 0,
        });
    }

    let target_count = targets.len();
    let receipt = execute_gc(&GcPlan { targets });
    let bytes_freed = receipt
        .actions
        .iter()
        .fold(0_u64, |acc, action| acc.saturating_add(action.bytes_freed));

    Ok(LaneLogGcSummary {
        targets: target_count,
        actions_applied: receipt.actions.len(),
        errors: receipt.errors.len(),
        bytes_freed,
    })
}

fn restart_worker_service_unit() -> Result<String, String> {
    let mut errors = Vec::new();
    for scope in SERVICE_SCOPES {
        let mut command = Command::new("systemctl");
        if let Some(scope_flag) = scope.scope_flag() {
            command.arg(scope_flag);
        }
        let output = command
            .args(["restart", "apm2-worker.service"])
            .output()
            .map_err(|err| {
                format!(
                    "failed to execute systemctl in {} scope: {err}",
                    scope.label()
                )
            });
        match output {
            Ok(output) if output.status.success() => return Ok(scope.label().to_string()),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                errors.push(format!(
                    "{} scope restart failed: {}",
                    scope.label(),
                    if stderr.is_empty() {
                        format!("exit {}", output.status.code().unwrap_or(-1))
                    } else {
                        stderr
                    }
                ));
            },
            Err(err) => errors.push(err),
        }
    }

    Err(format!(
        "failed to restart apm2-worker.service in all scopes: {}",
        errors.join("; ")
    ))
}

fn run_system_doctor_fix(
    operator_socket: &Path,
    config_path: &Path,
    full: bool,
    include_tracked_prs: bool,
    repo_filter: Option<&str>,
    json_output: bool,
) -> u8 {
    use apm2_core::fac::{OrphanedJobPolicy, reconcile_on_startup};
    use apm2_core::github::resolve_apm2_home;

    let before_snapshot = match collect_system_doctor_snapshot(
        operator_socket,
        config_path,
        full,
        include_tracked_prs,
        repo_filter,
    ) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return output_error(
                json_output,
                "fac_doctor_failed",
                &format!("failed to collect pre-fix doctor checks: {err}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let Some(home) = resolve_apm2_home() else {
        return output_error(
            json_output,
            "fac_doctor_fix_home_unresolved",
            "cannot resolve APM2 home for doctor --fix",
            exit_codes::GENERIC_ERROR,
        );
    };
    let fac_root = home.join("private").join("fac");
    let queue_root = home.join("queue");

    let manager = match LaneManager::new(fac_root.clone()) {
        Ok(manager) => manager,
        Err(err) => {
            return output_error(
                json_output,
                "fac_doctor_fix_lane_manager_init_failed",
                &format!("failed to initialize lane manager: {err}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let mut actions: Vec<SystemDoctorFixAction> = Vec::new();
    let mut action_failed = false;
    let mut should_restart_worker = false;
    let mut lane_resets_applied = false;

    match manager.reconcile_lanes() {
        Ok(receipt) => {
            let has_lane_errors = receipt.lanes_failed > 0
                || receipt.lanes_marked_corrupt > 0
                || receipt.infrastructure_failures > 0;
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::LaneReconcile,
                if has_lane_errors {
                    SystemDoctorFixActionStatus::Blocked
                } else {
                    SystemDoctorFixActionStatus::Applied
                },
                None,
                format!(
                    "inspected={} repaired={} marked_corrupt={} failed={} infra_failures={}",
                    receipt.lanes_inspected,
                    receipt.lanes_repaired,
                    receipt.lanes_marked_corrupt,
                    receipt.lanes_failed,
                    receipt.infrastructure_failures
                ),
            );
        },
        Err(err) => {
            action_failed = true;
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::LaneReconcile,
                SystemDoctorFixActionStatus::Failed,
                None,
                format!("lane reconcile failed: {err}"),
            );
        },
    }

    match reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false) {
        Ok(receipt) => {
            if receipt.stale_leases_recovered > 0
                || receipt.orphaned_jobs_requeued > 0
                || receipt.orphaned_jobs_failed > 0
                || receipt.torn_states_recovered > 0
            {
                should_restart_worker = true;
            }
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::QueueReconcileApply,
                SystemDoctorFixActionStatus::Applied,
                None,
                format!(
                    "lanes_inspected={} stale_leases_recovered={} orphaned_jobs_requeued={} orphaned_jobs_failed={} torn_states_recovered={} lanes_marked_corrupt={}",
                    receipt.lanes_inspected,
                    receipt.stale_leases_recovered,
                    receipt.orphaned_jobs_requeued,
                    receipt.orphaned_jobs_failed,
                    receipt.torn_states_recovered,
                    receipt.lanes_marked_corrupt
                ),
            );
        },
        Err(err) => {
            action_failed = true;
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::QueueReconcileApply,
                SystemDoctorFixActionStatus::Failed,
                None,
                format!("queue reconcile failed: {err}"),
            );
        },
    }

    match gc_stale_lane_logs(&fac_root, &manager) {
        Ok(summary) if summary.targets == 0 => {
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::LaneLogGc,
                SystemDoctorFixActionStatus::Skipped,
                None,
                "no stale lane log targets matched retention policy",
            );
        },
        Ok(summary) if summary.errors == 0 => {
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::LaneLogGc,
                SystemDoctorFixActionStatus::Applied,
                None,
                format!(
                    "targets={} actions={} bytes_freed={}",
                    summary.targets, summary.actions_applied, summary.bytes_freed
                ),
            );
        },
        Ok(summary) => {
            action_failed = true;
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::LaneLogGc,
                SystemDoctorFixActionStatus::Failed,
                None,
                format!(
                    "targets={} actions={} errors={} bytes_freed={}",
                    summary.targets, summary.actions_applied, summary.errors, summary.bytes_freed
                ),
            );
        },
        Err(err) => {
            action_failed = true;
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::LaneLogGc,
                SystemDoctorFixActionStatus::Failed,
                None,
                err,
            );
        },
    }

    let lane_statuses = match manager.all_lane_statuses() {
        Ok(statuses) => statuses,
        Err(err) => {
            action_failed = true;
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::LaneStatusScan,
                SystemDoctorFixActionStatus::Failed,
                None,
                format!("failed to load lane statuses: {err}"),
            );
            Vec::new()
        },
    };

    for status in lane_statuses {
        if status.state != LaneState::Corrupt {
            continue;
        }

        let lane_id = status.lane_id.clone();
        let reason_hint = load_lane_reason_hint(&manager, &status).unwrap_or_default();
        let reason_is_orphaned = reason_hint.contains(ORPHANED_SYSTEMD_UNIT_REASON_CODE);
        let reason_is_cleanup = should_attempt_cleanup_scrub(&reason_hint);
        let tmp_trigger_detail = match detect_lane_tmp_corruption(&manager, &lane_id) {
            Ok(value) => value,
            Err(err) => {
                action_failed = true;
                push_system_doctor_fix_action(
                    &mut actions,
                    SystemDoctorFixActionKind::LaneTmpCorruptionDetection,
                    SystemDoctorFixActionStatus::Failed,
                    Some(&lane_id),
                    err,
                );
                None
            },
        };
        let reason_is_tmp_corrupt = tmp_trigger_detail.is_some();
        if !reason_is_orphaned && !reason_is_cleanup && !reason_is_tmp_corrupt {
            continue;
        }

        if let Some(detail) = tmp_trigger_detail.as_ref() {
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::LaneTmpCorruptionDetected,
                SystemDoctorFixActionStatus::Blocked,
                Some(&lane_id),
                detail.clone(),
            );
            match scrub_lane_tmp_dir(&manager, &lane_id) {
                Ok(scrub_summary) => {
                    push_system_doctor_fix_action(
                        &mut actions,
                        SystemDoctorFixActionKind::LaneTmpScrub,
                        SystemDoctorFixActionStatus::Applied,
                        Some(&lane_id),
                        format!(
                            "tmp scrubbed (entries_deleted={})",
                            scrub_summary.entries_deleted
                        ),
                    );
                },
                Err(err) => {
                    action_failed = true;
                    push_system_doctor_fix_action(
                        &mut actions,
                        SystemDoctorFixActionKind::LaneTmpScrub,
                        SystemDoctorFixActionStatus::Failed,
                        Some(&lane_id),
                        err,
                    );
                    continue;
                },
            }
        }

        let reset_action = if reason_is_orphaned {
            SystemDoctorFixActionKind::LaneResetOrphanedSystemdUnit
        } else if reason_is_tmp_corrupt {
            SystemDoctorFixActionKind::LaneResetTmpCorruption
        } else {
            SystemDoctorFixActionKind::LaneResetCleanupRecovery
        };
        let job_id = status.job_id.clone().or_else(|| {
            LaneLeaseV1::load(&manager.lane_dir(&lane_id))
                .ok()
                .flatten()
                .map(|lease| lease.job_id)
        });
        if let Err(detail) =
            enforce_lane_reset_liveness_guard(&lane_id, job_id.as_deref(), check_fac_unit_liveness)
        {
            push_system_doctor_fix_action(
                &mut actions,
                reset_action,
                SystemDoctorFixActionStatus::Blocked,
                Some(&lane_id),
                detail,
            );
            continue;
        }
        match doctor_reset_lane_once(&manager, &lane_id) {
            Ok(reset_summary) => {
                lane_resets_applied = true;
                should_restart_worker = true;
                push_system_doctor_fix_action(
                    &mut actions,
                    reset_action,
                    SystemDoctorFixActionStatus::Applied,
                    Some(&lane_id),
                    format!(
                        "reset complete (files_deleted={}, dirs_deleted={})",
                        reset_summary.files_deleted, reset_summary.dirs_deleted
                    ),
                );
            },
            Err(DoctorLaneResetError::Running { pid }) => {
                push_system_doctor_fix_action(
                    &mut actions,
                    reset_action,
                    SystemDoctorFixActionStatus::Blocked,
                    Some(&lane_id),
                    format!(
                        "lane is RUNNING (pid={}); refusing non-force reset",
                        pid.unwrap_or(0)
                    ),
                );
            },
            Err(DoctorLaneResetError::RefusedDelete { receipts })
                if refused_delete_mentions_tmp(&receipts) =>
            {
                match scrub_lane_tmp_dir(&manager, &lane_id) {
                    Ok(scrub_summary) => {
                        push_system_doctor_fix_action(
                            &mut actions,
                            SystemDoctorFixActionKind::LaneTmpScrub,
                            SystemDoctorFixActionStatus::Applied,
                            Some(&lane_id),
                            format!(
                                "tmp scrubbed (entries_deleted={})",
                                scrub_summary.entries_deleted
                            ),
                        );
                        match doctor_reset_lane_once(&manager, &lane_id) {
                            Ok(reset_summary) => {
                                lane_resets_applied = true;
                                should_restart_worker = true;
                                push_system_doctor_fix_action(
                                    &mut actions,
                                    reset_action,
                                    SystemDoctorFixActionStatus::Applied,
                                    Some(&lane_id),
                                    format!(
                                        "reset complete after tmp scrub (files_deleted={}, dirs_deleted={})",
                                        reset_summary.files_deleted, reset_summary.dirs_deleted
                                    ),
                                );
                            },
                            Err(err) => {
                                action_failed = true;
                                push_system_doctor_fix_action(
                                    &mut actions,
                                    reset_action,
                                    SystemDoctorFixActionStatus::Failed,
                                    Some(&lane_id),
                                    format!("reset still failing after tmp scrub: {err:?}"),
                                );
                            },
                        }
                    },
                    Err(err) => {
                        action_failed = true;
                        push_system_doctor_fix_action(
                            &mut actions,
                            SystemDoctorFixActionKind::LaneTmpScrub,
                            SystemDoctorFixActionStatus::Failed,
                            Some(&lane_id),
                            err,
                        );
                    },
                }
            },
            Err(DoctorLaneResetError::RefusedDelete { receipts }) => {
                action_failed = true;
                let detail = receipts
                    .iter()
                    .map(|receipt| format!("{}: {}", receipt.root.display(), receipt.reason))
                    .collect::<Vec<_>>()
                    .join("; ");
                push_system_doctor_fix_action(
                    &mut actions,
                    reset_action,
                    SystemDoctorFixActionStatus::Failed,
                    Some(&lane_id),
                    format!("reset refused: {detail}"),
                );
            },
            Err(DoctorLaneResetError::Other(err)) => {
                action_failed = true;
                push_system_doctor_fix_action(
                    &mut actions,
                    reset_action,
                    SystemDoctorFixActionStatus::Failed,
                    Some(&lane_id),
                    err,
                );
            },
        }
    }

    if lane_resets_applied {
        match reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false) {
            Ok(receipt) => {
                push_system_doctor_fix_action(
                    &mut actions,
                    SystemDoctorFixActionKind::QueueReconcilePostLaneReset,
                    SystemDoctorFixActionStatus::Applied,
                    None,
                    format!(
                        "post-reset reconcile complete (stale_leases_recovered={}, orphaned_jobs_requeued={}, orphaned_jobs_failed={}, torn_states_recovered={})",
                        receipt.stale_leases_recovered,
                        receipt.orphaned_jobs_requeued,
                        receipt.orphaned_jobs_failed,
                        receipt.torn_states_recovered
                    ),
                );
            },
            Err(err) => {
                action_failed = true;
                push_system_doctor_fix_action(
                    &mut actions,
                    SystemDoctorFixActionKind::QueueReconcilePostLaneReset,
                    SystemDoctorFixActionStatus::Failed,
                    None,
                    format!("post-reset queue reconcile failed: {err}"),
                );
            },
        }
    } else {
        push_system_doctor_fix_action(
            &mut actions,
            SystemDoctorFixActionKind::QueueReconcilePostLaneReset,
            SystemDoctorFixActionStatus::Skipped,
            None,
            "no lane reset actions applied; post-reset reconcile skipped",
        );
    }

    if should_restart_worker {
        match restart_worker_service_unit() {
            Ok(scope) => {
                push_system_doctor_fix_action(
                    &mut actions,
                    SystemDoctorFixActionKind::WorkerRestart,
                    SystemDoctorFixActionStatus::Applied,
                    None,
                    format!("restarted apm2-worker.service in {scope} scope"),
                );
            },
            Err(err) => {
                action_failed = true;
                push_system_doctor_fix_action(
                    &mut actions,
                    SystemDoctorFixActionKind::WorkerRestart,
                    SystemDoctorFixActionStatus::Failed,
                    None,
                    err,
                );
            },
        }
    } else {
        push_system_doctor_fix_action(
            &mut actions,
            SystemDoctorFixActionKind::WorkerRestart,
            SystemDoctorFixActionStatus::Skipped,
            None,
            "no repair actions required worker restart",
        );
    }

    let after_snapshot = match collect_system_doctor_snapshot(
        operator_socket,
        config_path,
        full,
        include_tracked_prs,
        repo_filter,
    ) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            action_failed = true;
            push_system_doctor_fix_action(
                &mut actions,
                SystemDoctorFixActionKind::DoctorPostCheck,
                SystemDoctorFixActionStatus::Failed,
                None,
                format!("failed to collect post-fix checks: {err}"),
            );
            DoctorSystemSnapshot {
                checks: Vec::new(),
                tracked_prs: Vec::new(),
                has_critical_error: true,
            }
        },
    };

    let response = SystemDoctorFixResponse {
        schema: FAC_DOCTOR_SYSTEM_FIX_SCHEMA.to_string(),
        actions,
        checks_before: before_snapshot.checks,
        checks_after: after_snapshot.checks,
        tracked_prs: after_snapshot.tracked_prs,
        had_errors_before: before_snapshot.has_critical_error,
        has_errors_after: after_snapshot.has_critical_error,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
    );

    let has_blocked_actions = response
        .actions
        .iter()
        .any(|action| action.status == SystemDoctorFixActionStatus::Blocked);
    system_doctor_fix_exit_code(
        action_failed,
        has_blocked_actions,
        after_snapshot.has_critical_error,
    )
}

fn run_services_status(_json_output: bool) -> u8 {
    let current_boot_micros = read_boot_time_micros();
    let mut services = Vec::with_capacity(SERVICES_UNIT_NAMES.len());
    let mut degraded = false;

    for unit_name in SERVICES_UNIT_NAMES {
        let status = match query_unit_status_with_scopes(unit_name, current_boot_micros) {
            Ok(status) => status,
            Err(message) => {
                degraded = true;
                ServiceStatusResponse {
                    unit: unit_name.to_string(),
                    scope: "none".to_string(),
                    load_state: "unknown".to_string(),
                    active_state: "unknown".to_string(),
                    sub_state: "unknown".to_string(),
                    enabled: "unknown".to_string(),
                    main_pid: 0,
                    uptime_seconds: 0,
                    watchdog_sec: 0,
                    health: "unhealthy".to_string(),
                    error: Some(message),
                }
            },
        };

        if status.health != "healthy" {
            degraded = true;
        }

        services.push(status);
    }

    // TCK-00600: Read worker heartbeat for liveness assessment.
    let fac_root =
        apm2_core::github::resolve_apm2_home().map(|home| home.join("private").join("fac"));
    let worker_heartbeat = fac_root
        .as_ref()
        .map(|root| apm2_core::fac::worker_heartbeat::read_heartbeat(root));

    // TCK-00600: If the worker service is active but heartbeat is stale OR
    // read failed, mark as degraded. This covers both staleness (found=true,
    // fresh=false) and read failures (found=false or error=Some).
    let worker_active = services
        .iter()
        .any(|s| s.unit.contains("worker") && s.active_state == "active");
    if let Some(ref hb) = worker_heartbeat {
        if hb.found && !hb.fresh {
            // Stale heartbeat while worker claims to be active.
            degraded = true;
        } else if worker_active && !hb.found {
            // Worker is active but heartbeat file missing or read error.
            degraded = true;
        }
    }

    // TCK-00600: Read broker health IPC for version + readiness assessment.
    // This is the source of truth for whether the daemon's internal health
    // checks are passing, independent of systemd unit state.
    let broker_health = fac_root
        .as_ref()
        .map(|root| apm2_core::fac::broker_health_ipc::read_broker_health(root));

    // TCK-00600: If broker health is available and reports unhealthy/degraded
    // or is stale, mark overall status as degraded.
    if let Some(ref bh) = broker_health {
        if bh.found && (!bh.fresh || bh.health_status != "healthy") {
            degraded = true;
        }
    }

    let (orphaned_systemd_units, orphaned_systemd_unit_error) = fac_root.as_ref().map_or_else(
        || (Vec::new(), None),
        |root| match collect_orphaned_systemd_units(root) {
            Ok(units) => {
                if !units.is_empty() {
                    degraded = true;
                }
                (units, None)
            },
            Err(err) => {
                degraded = true;
                (Vec::new(), Some(err))
            },
        },
    );

    let overall_health = if degraded { "degraded" } else { "healthy" }.to_string();

    let response = ServicesStatusResponse {
        overall_health,
        services: services.clone(),
        worker_heartbeat,
        broker_health,
        orphaned_systemd_units,
        orphaned_systemd_unit_error,
    };
    if let Ok(json) = serde_json::to_string_pretty(&response) {
        println!("{json}");
    } else {
        println!("{{\"overall_health\":\"unhealthy\",\"services\":[]}}");
        degraded = true;
    }

    if degraded {
        exit_codes::GENERIC_ERROR
    } else {
        exit_codes::SUCCESS
    }
}

fn query_unit_status_with_scopes(
    unit_name: &'static str,
    current_boot_micros: Option<u128>,
) -> Result<ServiceStatusResponse, String> {
    let mut last_error: Option<String> = None;

    for scope in SERVICE_SCOPES {
        match query_unit_status(scope, unit_name, current_boot_micros) {
            Ok(service_status) => return Ok(service_status),
            Err(error) => last_error = Some(format!("{} ({} scope)", error, scope.label())),
        }
    }

    Err(last_error.unwrap_or_else(|| format!("unit {unit_name} not found in user or system scope")))
}

fn query_unit_status(
    scope: ServiceScope,
    unit_name: &'static str,
    current_boot_micros: Option<u128>,
) -> Result<ServiceStatusResponse, String> {
    let mut cmd = Command::new("systemctl");
    if let Some(flag) = scope.scope_flag() {
        cmd.arg(flag);
    }
    cmd.arg("show");
    cmd.args(SERVICE_STATUS_PROPERTIES.map(|property| format!("--property={property}")));
    cmd.arg(unit_name);

    let output = cmd.output().map_err(|error| {
        format!(
            "failed to run systemctl for {unit_name} in {} scope: {error}",
            scope.label()
        )
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "systemctl status check failed for {unit_name} in {} scope: {}",
            scope.label(),
            stderr.trim()
        ));
    }

    parse_systemctl_show_output(unit_name, scope, current_boot_micros, &output.stdout)
}

fn parse_systemctl_show_output(
    unit_name: &'static str,
    scope: ServiceScope,
    current_boot_micros: Option<u128>,
    raw_output: &[u8],
) -> Result<ServiceStatusResponse, String> {
    let output = String::from_utf8_lossy(raw_output);
    let mut load_state = String::new();
    let mut active_state = String::new();
    let mut sub_state = String::new();
    let mut enabled = String::new();
    let mut main_pid = String::new();
    let mut active_enter_timestamp = String::new();
    let mut watchdog_usec = String::new();

    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "LoadState" => load_state = value.to_string(),
                "ActiveState" => active_state = value.to_string(),
                "SubState" => sub_state = value.to_string(),
                "UnitFileState" => enabled = value.to_string(),
                "MainPID" => main_pid = value.to_string(),
                "ActiveEnterTimestampMonotonic" => active_enter_timestamp = value.to_string(),
                "WatchdogUSec" => watchdog_usec = value.to_string(),
                _ => {},
            }
        }
    }

    if load_state.is_empty() || active_state.is_empty() || sub_state.is_empty() {
        return Err(format!(
            "systemctl output for {unit_name} ({}) is missing expected fields",
            scope.label()
        ));
    }

    let main_pid: u32 = main_pid.parse().unwrap_or(0);
    let active_enter: Option<u128> = if active_enter_timestamp.is_empty() {
        None
    } else {
        active_enter_timestamp.parse().ok()
    };
    let uptime_seconds = compute_service_uptime(current_boot_micros, active_enter);

    // TCK-00600: Parse watchdog timeout from usec to seconds.
    let watchdog_timeout_secs = watchdog_usec
        .parse::<u64>()
        .ok()
        .map_or(0, |usec| usec / 1_000_000);

    // TCK-00600: Compute deterministic health verdict.
    // healthy = loaded + active + enabled
    // degraded = loaded but not active (e.g., activating, reloading)
    // unhealthy = not loaded, failed, or errored
    let health = if load_state == "loaded" && active_state == "active" && enabled == "enabled" {
        "healthy"
    } else if load_state == "loaded" && active_state != "failed" {
        "degraded"
    } else {
        "unhealthy"
    }
    .to_string();

    Ok(ServiceStatusResponse {
        unit: unit_name.to_string(),
        scope: scope.label().to_string(),
        load_state,
        active_state,
        sub_state,
        enabled,
        main_pid,
        uptime_seconds,
        watchdog_sec: watchdog_timeout_secs,
        health,
        error: None,
    })
}

fn compute_service_uptime(
    current_boot_micros: Option<u128>,
    active_enter_micros: Option<u128>,
) -> u64 {
    match (current_boot_micros, active_enter_micros) {
        (Some(boot), Some(enter)) if boot >= enter => {
            let elapsed_micros = boot.saturating_sub(enter);
            u64::try_from(elapsed_micros / 1_000_000).unwrap_or_default()
        },
        _ => 0,
    }
}

fn read_boot_time_micros() -> Option<u128> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let raw_seconds = uptime.split_whitespace().next()?;
    parse_uptime_microseconds(raw_seconds)
}

fn parse_uptime_microseconds(raw_seconds: &str) -> Option<u128> {
    let (whole_seconds, fractional_seconds) =
        raw_seconds.split_once('.').unwrap_or((raw_seconds, "0"));
    let seconds = whole_seconds.parse::<u128>().ok()?;

    let mut microseconds = 0_u128;
    let mut scale = 6_u32;
    for ch in fractional_seconds.chars().take(6) {
        let digit = ch.to_digit(10)?;
        scale = scale.saturating_sub(1);
        microseconds =
            microseconds.saturating_add(u128::from(digit) * 10_u128.saturating_pow(scale));
    }

    Some(
        seconds
            .saturating_mul(1_000_000)
            .saturating_add(microseconds),
    )
}

// =============================================================================
// Command Execution
// =============================================================================

/// Runs the FAC command, returning an appropriate exit code.
///
/// TCK-00595 MAJOR-2 FIX: `config_path` is threaded through so the
/// `ensure_daemon_running` fallback spawn uses the same config the caller
/// specified via `--config`.
pub fn run_fac(
    cmd: &FacCommand,
    operator_socket: &Path,
    session_socket: &Path,
    config_path: &Path,
) -> u8 {
    // TCK-00606 S12 invariant: FAC commands are machine-output only.
    let machine_output = subcommand_requests_machine_output(&cmd.subcommand);
    let json_output = machine_output;
    let resolve_json = |_subcommand_json: bool| -> bool { machine_output };

    // TCK-00577 round 3: Enqueue-class commands (push, gates, warm) may be
    // invoked by non-service-user callers in a service-user-owned deployment.
    // These callers cannot satisfy the strict ownership check on FAC roots
    // (directories are owned by the service user). Use a relaxed validation
    // that checks mode bits and symlink safety but NOT ownership, so the
    // caller can reach enqueue_job → broker fallback → broker_requests/.
    // All other commands require strict ownership validation.
    // TCK-00577 round 6: Bench spawns gate measurements as child processes
    // that need the relaxed permission validation path (same as enqueue-class
    // commands), so include it here.
    // TCK-00577 round 9 MAJOR fix: Worker and Broker subcommands must also
    // use relaxed validation. The worker itself sets queue/ to 0711 and
    // broker_requests/ to 01733 via ensure_queue_dirs(). The strict validator
    // (0700-only) rejects these intentional modes, causing worker restart to
    // fail at preflight after mode hardening. The relaxed validator permits
    // execute-only traversal bits (0o011) while still rejecting read/write
    // group/other bits.
    let is_enqueue_class = matches!(
        cmd.subcommand,
        FacSubcommand::Push(_)
            | FacSubcommand::Gates(_)
            | FacSubcommand::Warm(_)
            | FacSubcommand::Bench(_)
            | FacSubcommand::Worker(_)
            | FacSubcommand::Broker(_)
    );
    let permissions_result = if is_enqueue_class {
        crate::commands::fac_permissions::validate_fac_root_permissions_relaxed_for_enqueue()
    } else {
        crate::commands::fac_permissions::validate_fac_root_permissions()
    };
    if let Err(err) = permissions_result {
        return output_error(
            machine_output,
            "fac_root_permissions_failed",
            &format!("FAC root permissions check failed (fail-closed): {err}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    let ledger_path = resolve_ledger_path(cmd.ledger_path.as_deref());
    let cas_path = resolve_cas_path(cmd.cas_path.as_deref());

    if !matches!(
        cmd.subcommand,
        FacSubcommand::Gates(_)
            | FacSubcommand::Preflight(_)
            | FacSubcommand::Doctor(_)
            | FacSubcommand::Install(_)
            | FacSubcommand::Lane(_)
            | FacSubcommand::Services(_)
            | FacSubcommand::Worker(_)
            | FacSubcommand::Broker(_)
            | FacSubcommand::Recover(_)
            | FacSubcommand::Gc(_)
            | FacSubcommand::Quarantine(_)
            | FacSubcommand::Job(_)
            | FacSubcommand::Verify(_)
            | FacSubcommand::Warm(_)
            | FacSubcommand::Bench(_)
            | FacSubcommand::Bundle(_)
            | FacSubcommand::Queue(_)
            | FacSubcommand::Policy(_)
            | FacSubcommand::Economics(_)
            | FacSubcommand::Bootstrap(_)
            | FacSubcommand::Config(_)
            | FacSubcommand::Metrics(_)
            | FacSubcommand::Caches(_)
    ) {
        if let Err(e) = crate::commands::daemon::ensure_daemon_running(operator_socket, config_path)
        {
            eprintln!("WARNING: Could not auto-start daemon: {e}");
        }
    }

    match &cmd.subcommand {
        FacSubcommand::Gates(args) => fac_review::run_gates(
            args.force,
            args.quick,
            args.timeout_seconds,
            &args.memory_max,
            args.pids_max,
            &args.cpu_quota,
            args.gate_profile,
            resolve_json(args.json),
            args.wait && !args.no_wait,
            args.wait_timeout_secs,
            cmd.queue_write_mode(),
        ),
        FacSubcommand::Preflight(args) => match &args.subcommand {
            PreflightSubcommand::Credential(credential_args) => fac_preflight::run_credential(
                credential_args.mode,
                &credential_args.paths,
                resolve_json(credential_args.json),
            ),
            PreflightSubcommand::Authorization(auth_args) => {
                fac_preflight::run_workflow_authorization(resolve_json(auth_args.json))
            },
        },
        FacSubcommand::Work(args) => match &args.subcommand {
            WorkSubcommand::Status(status_args) => {
                run_work_status(status_args, operator_socket, resolve_json(status_args.json))
            },
            WorkSubcommand::List(list_args) => {
                run_work_list(list_args, operator_socket, resolve_json(list_args.json))
            },
        },
        FacSubcommand::Install(args) => crate::commands::fac_install::run_install(
            resolve_json(args.json),
            args.allow_partial,
            args.workspace_root.as_deref(),
        ),
        FacSubcommand::Doctor(args) => {
            let output_json = resolve_json(args.json);
            if args.machine_spec {
                match fac_review::fac_review_machine_spec_json_string(output_json) {
                    Ok(rendered) => {
                        println!("{rendered}");
                        return exit_codes::SUCCESS;
                    },
                    Err(err) => {
                        return output_error(
                            output_json,
                            "fac_doctor_machine_spec_serialize_failed",
                            &err,
                            exit_codes::GENERIC_ERROR,
                        );
                    },
                }
            }
            if args.wait_for_recommended_action && args.pr.is_none() {
                return output_error(
                    output_json,
                    "fac_doctor_wait_requires_pr",
                    "`--wait-for-recommended-action` requires `--pr <N>`",
                    exit_codes::GENERIC_ERROR,
                );
            }
            if args.wait_for_recommended_action && args.fix {
                return output_error(
                    output_json,
                    "fac_doctor_wait_incompatible_fix",
                    "`--wait-for-recommended-action` is incompatible with `--fix`",
                    exit_codes::GENERIC_ERROR,
                );
            }
            if let Some(pr) = args.pr {
                let repo = match derive_fac_repo_or_exit(output_json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                let exit_on = args
                    .exit_on
                    .iter()
                    .map(|value| value.as_str().to_string())
                    .collect::<Vec<_>>();
                fac_review::run_doctor(
                    &repo,
                    pr,
                    args.fix,
                    output_json,
                    args.wait_for_recommended_action,
                    args.poll_interval_seconds,
                    args.wait_timeout_seconds,
                    &exit_on,
                )
            } else if args.fix {
                run_system_doctor_fix(
                    operator_socket,
                    config_path,
                    args.full,
                    args.tracked_prs || args.full,
                    args.repo.as_deref(),
                    output_json,
                )
            } else {
                let snapshot = match collect_system_doctor_snapshot(
                    operator_socket,
                    config_path,
                    args.full,
                    args.tracked_prs || args.full,
                    args.repo.as_deref(),
                ) {
                    Ok(snapshot) => snapshot,
                    Err(err) => {
                        return output_error(
                            output_json,
                            "fac_doctor_failed",
                            &err,
                            exit_codes::GENERIC_ERROR,
                        );
                    },
                };
                emit_system_doctor_snapshot(&snapshot);

                if snapshot.has_critical_error {
                    exit_codes::GENERIC_ERROR
                } else {
                    exit_codes::SUCCESS
                }
            }
        },
        FacSubcommand::Services(args) => match &args.subcommand {
            ServicesSubcommand::Status(status_args) => {
                run_services_status(resolve_json(status_args.json))
            },
        },
        FacSubcommand::RoleLaunch(args) => {
            let output_json = resolve_json(false);
            match role_launch::handle_role_launch(
                args,
                &ledger_path,
                &cas_path,
                session_socket,
                output_json,
            ) {
                Ok(()) => exit_codes::SUCCESS,
                Err(error) => error
                    .downcast_ref::<role_launch::RoleLaunchError>()
                    .map_or_else(
                        || {
                            output_error(
                                output_json,
                                "role_launch_error",
                                &format!("role launch failed: {error}"),
                                exit_codes::GENERIC_ERROR,
                            )
                        },
                        role_launch::RoleLaunchError::exit_code,
                    ),
            }
        },
        FacSubcommand::Episode(args) => match &args.subcommand {
            EpisodeSubcommand::Inspect(inspect_args) => run_episode_inspect(
                inspect_args,
                &ledger_path,
                &cas_path,
                resolve_json(inspect_args.json),
            ),
        },
        FacSubcommand::Receipts(args) => match &args.subcommand {
            ReceiptSubcommand::Show(show_args) => {
                run_receipt_show(show_args, &cas_path, resolve_json(show_args.json))
            },
            ReceiptSubcommand::List(list_args) => {
                run_receipt_list(list_args, resolve_json(list_args.json))
            },
            ReceiptSubcommand::Status(status_args) => {
                run_receipt_status(status_args, resolve_json(status_args.json))
            },
            ReceiptSubcommand::Reindex(reindex_args) => {
                run_receipt_reindex(resolve_json(reindex_args.json))
            },
            ReceiptSubcommand::Verify(verify_args) => {
                run_receipt_verify(verify_args, resolve_json(verify_args.json))
            },
            ReceiptSubcommand::Merge(merge_args) => {
                run_receipt_merge(merge_args, resolve_json(merge_args.json))
            },
        },
        FacSubcommand::Context(args) => match &args.subcommand {
            ContextSubcommand::Rebuild(rebuild_args) => run_context_rebuild(
                rebuild_args,
                &ledger_path,
                &cas_path,
                resolve_json(rebuild_args.json),
            ),
        },
        FacSubcommand::Lane(args) => match &args.subcommand {
            LaneSubcommand::Status(status_args) => {
                run_lane_status(status_args, resolve_json(status_args.json))
            },
            LaneSubcommand::Init(init_args) => {
                run_lane_init(init_args, resolve_json(init_args.json))
            },
            LaneSubcommand::MarkCorrupt(mark_args) => {
                run_lane_mark_corrupt(mark_args, resolve_json(mark_args.json))
            },
        },
        FacSubcommand::Push(args) => {
            let output_json = resolve_json(args.json);
            let repo = match derive_fac_repo_or_exit(machine_output) {
                Ok(value) => value,
                Err(code) => return code,
            };
            fac_review::run_push(
                &repo,
                &args.remote,
                args.branch.as_deref(),
                args.ticket.as_deref(),
                output_json,
                cmd.queue_write_mode(),
            )
        },
        FacSubcommand::Restart(args) => {
            let output_json = resolve_json(args.json);
            let repo = match derive_fac_repo_or_exit(machine_output) {
                Ok(value) => value,
                Err(code) => return code,
            };
            fac_review::run_restart(
                &repo,
                args.pr,
                args.force,
                args.refresh_identity,
                output_json,
            )
        },
        FacSubcommand::Recover(args) => {
            let output_json = resolve_json(args.json);
            let repo = match derive_fac_repo_or_exit(output_json) {
                Ok(value) => value,
                Err(code) => return code,
            };
            fac_review::run_recover(
                &repo,
                args.pr,
                args.force,
                args.refresh_identity,
                args.reap_stale_agents,
                args.reset_lifecycle,
                args.all,
                output_json,
            )
        },
        FacSubcommand::Logs(args) => {
            let output_json = resolve_json(args.json);
            let repo = match derive_fac_repo_or_exit(output_json) {
                Ok(value) => value,
                Err(code) => return code,
            };
            fac_review::run_logs(
                args.pr,
                &repo,
                args.selector_type.as_deref(),
                args.selector.as_deref(),
                output_json,
            )
        },
        FacSubcommand::Pipeline(args) => {
            let output_json = resolve_json(args.json);
            let repo = match derive_fac_repo_or_exit(output_json) {
                Ok(value) => value,
                Err(code) => return code,
            };
            fac_review::run_pipeline(&repo, args.pr, &args.sha, output_json)
        },
        FacSubcommand::Review(args) => match &args.subcommand {
            ReviewSubcommand::Run(run_args) => {
                let output_json = resolve_json(run_args.json);
                let repo = match derive_fac_repo_or_exit(machine_output) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_review(
                    &repo,
                    run_args.pr,
                    run_args.review_type,
                    run_args.expected_head_sha.as_deref(),
                    run_args.force,
                    output_json,
                )
            },
            ReviewSubcommand::Prepare(prepare_args) => {
                let output_json = resolve_json(prepare_args.json);
                let repo = match derive_fac_repo_or_exit(output_json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_prepare(
                    &repo,
                    prepare_args.pr,
                    prepare_args.sha.as_deref(),
                    output_json,
                )
            },
            ReviewSubcommand::Finding(finding_args) => {
                let output_json = resolve_json(finding_args.json);
                let repo = match derive_fac_repo_or_exit(output_json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_finding(
                    &repo,
                    finding_args.pr,
                    finding_args.sha.as_deref(),
                    finding_args.review_type,
                    finding_args.severity,
                    &finding_args.summary,
                    finding_args.details.as_deref(),
                    finding_args.risk.as_deref(),
                    finding_args.impact.as_deref(),
                    finding_args.location.as_deref(),
                    finding_args.reviewer_id.as_deref(),
                    finding_args.model_id.as_deref(),
                    finding_args.backend_id.as_deref(),
                    finding_args.evidence_pointer.as_deref(),
                    output_json,
                )
            },
            ReviewSubcommand::Comment(comment_args) => {
                let output_json = resolve_json(comment_args.json);
                let repo = match derive_fac_repo_or_exit(output_json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_comment_compat(
                    &repo,
                    comment_args.pr,
                    comment_args.sha.as_deref(),
                    comment_args.review_type,
                    comment_args.severity,
                    comment_args.body.as_deref(),
                    output_json,
                )
            },
            ReviewSubcommand::Findings(findings_args) => {
                let output_json = resolve_json(findings_args.json);
                let repo = match derive_fac_repo_or_exit(output_json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_findings(
                    &repo,
                    findings_args.pr,
                    findings_args.sha.as_deref(),
                    findings_args.refresh,
                    output_json,
                )
            },
            ReviewSubcommand::Verdict(verdict_args) => match &verdict_args.subcommand {
                ReviewVerdictSubcommand::Show(show_args) => {
                    let output_json = resolve_json(show_args.json);
                    let repo = match derive_fac_repo_or_exit(output_json) {
                        Ok(value) => value,
                        Err(code) => return code,
                    };
                    fac_review::run_verdict_show(
                        &repo,
                        show_args.pr,
                        show_args.sha.as_deref(),
                        output_json,
                    )
                },
                ReviewVerdictSubcommand::Set(set_args) => {
                    let output_json = resolve_json(set_args.json);
                    let repo = match derive_fac_repo_or_exit(output_json) {
                        Ok(value) => value,
                        Err(code) => return code,
                    };
                    fac_review::run_verdict_set(
                        &repo,
                        set_args.pr,
                        set_args.sha.as_deref(),
                        &set_args.dimension,
                        set_args.verdict,
                        set_args.reason.as_deref(),
                        set_args.model_id.as_deref(),
                        set_args.backend_id.as_deref(),
                        set_args.keep_prepared_inputs,
                        output_json,
                    )
                },
            },
            ReviewSubcommand::Tail(tail_args) => {
                fac_review::run_tail(tail_args.lines, tail_args.follow)
            },
            ReviewSubcommand::Terminate(term_args) => {
                let output_json = resolve_json(term_args.json);
                let repo = match derive_fac_repo_or_exit(output_json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_terminate(
                    &repo,
                    term_args.pr,
                    term_args.review_type.as_str(),
                    output_json,
                )
            },
        },
        FacSubcommand::Worker(args) => crate::commands::fac_worker::run_fac_worker(
            args.once,
            args.poll_interval_secs,
            args.max_jobs,
            resolve_json(args.json),
            args.print_unit,
        ),
        FacSubcommand::Job(args) => match &args.subcommand {
            JobSubcommand::Cancel(cancel_args) => {
                crate::commands::fac_job::run_cancel(cancel_args, resolve_json(cancel_args.json))
            },
            JobSubcommand::Show(show_args) => crate::commands::fac_job::run_job_show(
                &show_args.job_id,
                resolve_json(show_args.json),
            ),
        },
        FacSubcommand::Queue(args) => match &args.subcommand {
            QueueSubcommand::Status(status_args) => crate::commands::fac_queue::run_queue_status(
                status_args,
                resolve_json(status_args.json),
            ),
        },
        FacSubcommand::Pr(args) => fac_pr::run_pr(args, json_output),
        FacSubcommand::Broker(args) => fac_broker::run_broker(args, json_output),
        FacSubcommand::Gc(args) => fac_gc::run_gc(args, json_output),
        FacSubcommand::Quarantine(args) => fac_quarantine::run_quarantine(args, json_output),
        FacSubcommand::Verify(args) => match &args.subcommand {
            VerifySubcommand::Containment(containment_args) => {
                run_verify_containment(containment_args, resolve_json(containment_args.json))
            },
        },
        FacSubcommand::Warm(args) => crate::commands::fac_warm::run_fac_warm(
            &args.phases,
            &args.lane,
            args.wait,
            args.wait_timeout_secs,
            resolve_json(args.json),
            cmd.queue_write_mode(),
        ),
        FacSubcommand::Bench(args) => crate::commands::fac_bench::run_fac_bench(
            args.concurrency,
            args.skip_warm,
            args.timeout_seconds,
            &args.memory_max,
            args.pids_max,
            &args.cpu_quota,
            resolve_json(args.json),
            cmd.queue_write_mode(),
        ),
        FacSubcommand::Bundle(args) => match &args.subcommand {
            BundleSubcommand::Export(export_args) => {
                run_bundle_export(export_args, resolve_json(export_args.json))
            },
            BundleSubcommand::Import(import_args) => {
                run_bundle_import(import_args, resolve_json(import_args.json))
            },
        },
        FacSubcommand::Policy(args) => fac_policy::run_policy_command(args, json_output),
        FacSubcommand::Economics(args) => fac_economics::run_economics_command(args, json_output),
        FacSubcommand::Bootstrap(args) => {
            crate::commands::fac_bootstrap::run_bootstrap(args, operator_socket, config_path)
        },
        FacSubcommand::Config(args) => {
            crate::commands::fac_config::run_config_command(args, json_output)
        },
        FacSubcommand::Metrics(args) => run_metrics(args, json_output),
        FacSubcommand::Caches(args) => {
            crate::commands::fac_caches::run_caches_command(args, json_output)
        },
    }
}

const fn subcommand_requests_machine_output(subcommand: &FacSubcommand) -> bool {
    match subcommand {
        FacSubcommand::Gates(_)
        | FacSubcommand::Preflight(_)
        | FacSubcommand::Work(_)
        | FacSubcommand::Doctor(_)
        | FacSubcommand::Services(_)
        | FacSubcommand::RoleLaunch(_)
        | FacSubcommand::Episode(_)
        | FacSubcommand::Receipts(_)
        | FacSubcommand::Context(_)
        | FacSubcommand::Lane(_)
        | FacSubcommand::Push(_)
        | FacSubcommand::Restart(_)
        | FacSubcommand::Recover(_)
        | FacSubcommand::Logs(_)
        | FacSubcommand::Pipeline(_)
        | FacSubcommand::Review(_)
        | FacSubcommand::Worker(_)
        | FacSubcommand::Job(_)
        | FacSubcommand::Pr(_)
        | FacSubcommand::Broker(_)
        | FacSubcommand::Gc(_)
        | FacSubcommand::Quarantine(_)
        | FacSubcommand::Verify(_)
        | FacSubcommand::Warm(_)
        | FacSubcommand::Bench(_)
        | FacSubcommand::Bundle(_)
        | FacSubcommand::Queue(_)
        | FacSubcommand::Policy(_)
        | FacSubcommand::Economics(_)
        | FacSubcommand::Bootstrap(_)
        | FacSubcommand::Config(_)
        | FacSubcommand::Metrics(_)
        | FacSubcommand::Caches(_)
        | FacSubcommand::Install(_) => true,
    }
}

/// Resolves the ledger path from explicit path, env var, or default.
fn resolve_ledger_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }

    if let Ok(data_dir) = std::env::var("APM2_DATA_DIR") {
        return PathBuf::from(data_dir).join(DEFAULT_LEDGER_FILENAME);
    }

    // Default to XDG data directory
    directories::ProjectDirs::from("com", "apm2", "apm2").map_or_else(
        || PathBuf::from("/var/lib/apm2").join(DEFAULT_LEDGER_FILENAME),
        |dirs| dirs.data_dir().join(DEFAULT_LEDGER_FILENAME),
    )
}

/// Resolves the CAS path from explicit path, env var, or default.
fn resolve_cas_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }

    if let Ok(data_dir) = std::env::var("APM2_DATA_DIR") {
        return PathBuf::from(data_dir).join(DEFAULT_CAS_DIRNAME);
    }

    // Default to XDG data directory
    directories::ProjectDirs::from("com", "apm2", "apm2").map_or_else(
        || PathBuf::from("/var/lib/apm2").join(DEFAULT_CAS_DIRNAME),
        |dirs| dirs.data_dir().join(DEFAULT_CAS_DIRNAME),
    )
}

/// Opens the ledger at the given path.
fn open_ledger(path: &Path) -> Result<Ledger, LedgerError> {
    if !path.exists() {
        return Err(LedgerError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Ledger not found at: {}", path.display()),
        )));
    }
    Ledger::open(path)
}

/// Calculates the starting cursor for a scan based on the limit and ledger
/// head.
///
/// Returns the start sequence ID.
fn calculate_start_cursor(ledger: &Ledger, limit: u64) -> Result<u64, LedgerError> {
    let max_seq = ledger.head_sync()?;
    Ok(max_seq.saturating_sub(limit).max(1))
}

// =============================================================================
// Work Status Command
// =============================================================================

/// Execute the work status command.
fn run_work_status(args: &WorkStatusArgs, operator_socket: &Path, json_output: bool) -> u8 {
    // Validate work ID
    if args.work_id.is_empty() {
        return output_error(
            json_output,
            "invalid_work_id",
            "Work ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Build async runtime
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            return output_error(
                json_output,
                "runtime_error",
                &format!("Failed to build tokio runtime: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let result = rt.block_on(async {
        let mut client = OperatorClient::connect(operator_socket).await?;
        client.work_status(&args.work_id).await
    });

    match result {
        Ok(response) => {
            let response = fac_work_status_from_daemon(response);

            println!(
                "{}",
                serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
            );

            exit_codes::SUCCESS
        },
        Err(error) => handle_protocol_error(json_output, &error),
    }
}

/// Execute the work list command.
fn run_work_list(args: &WorkListArgs, operator_socket: &Path, json_output: bool) -> u8 {
    #[derive(Debug, Serialize)]
    struct WorkListJson<'a> {
        claimable_only: bool,
        total: usize,
        items: &'a [WorkStatusResponse],
    }

    // Build async runtime
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            return output_error(
                json_output,
                "runtime_error",
                &format!("Failed to build tokio runtime: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let result = rt.block_on(async {
        let mut client = OperatorClient::connect(operator_socket).await?;
        client.work_list(args.claimable_only).await
    });

    match result {
        Ok(response) => {
            let rows: Vec<WorkStatusResponse> = response
                .work_items
                .into_iter()
                .map(fac_work_status_from_daemon)
                .collect();

            let output = WorkListJson {
                claimable_only: args.claimable_only,
                total: rows.len(),
                items: &rows,
            };

            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
            );

            exit_codes::SUCCESS
        },
        Err(error) => handle_protocol_error(json_output, &error),
    }
}

fn fac_work_status_from_daemon(
    response: apm2_daemon::protocol::WorkStatusResponse,
) -> WorkStatusResponse {
    let role = response
        .role
        .and_then(|value| WorkRole::try_from(value).ok())
        .map(|role| format!("{role:?}"));

    WorkStatusResponse {
        work_id: response.work_id,
        status: response.status,
        actor_id: response.actor_id,
        role,
        latest_episode_id: response.session_id,
        latest_receipt_hash: response.lease_id,
        event_count: 1,
        latest_seq_id: None,
    }
}

/// Extracted work information from an event.
#[cfg(test)]
struct WorkInfo {
    episode_id: Option<String>,
}

/// Extracts work-related information from an event if it matches the `work_id`.
#[cfg(test)]
fn extract_work_info(event: &EventRecord, work_id: &str) -> Option<WorkInfo> {
    // TCK-00398 Phase 1 compatibility:
    // - Prefer metadata-derived work_id (`session_id`) when present.
    // - Fall back to payload work_id for legacy rows where the daemon stores
    //   episode IDs in `work_id`.
    let payload = serde_json::from_slice::<serde_json::Value>(&event.payload).ok();

    let metadata_work_id_match = event.session_id == work_id;
    let payload_work_id_match = payload
        .as_ref()
        .and_then(|v| v.get("work_id"))
        .and_then(|v| v.as_str())
        .is_some_and(|id| id == work_id);

    if !metadata_work_id_match && !payload_work_id_match {
        return None;
    }

    Some(WorkInfo {
        episode_id: payload
            .as_ref()
            .and_then(|v| v.get("episode_id"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| {
                (event.event_type == "episode_spawned" && payload_work_id_match)
                    .then(|| event.session_id.clone())
            }),
    })
}

// =============================================================================
// Episode Inspect Command
// =============================================================================

/// Execute the episode inspect command.
fn run_episode_inspect(
    args: &EpisodeInspectArgs,
    ledger_path: &Path,
    cas_path: &Path,
    json_output: bool,
) -> u8 {
    // Validate episode ID
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_episode_id",
            "Episode ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Open ledger
    let ledger = match open_ledger(ledger_path) {
        Ok(l) => l,
        Err(e) => {
            return output_error(
                json_output,
                "ledger_error",
                &format!("Failed to open ledger: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Calculate start cursor based on limit
    let mut cursor = match calculate_start_cursor(&ledger, args.limit) {
        Ok(c) => c,
        Err(e) => {
            return output_error(
                json_output,
                "ledger_error",
                &format!("Failed to query ledger head: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Scan ledger for episode-related events
    let mut response = EpisodeInspectResponse {
        episode_id: args.episode_id.clone(),
        status: "UNKNOWN".to_string(),
        work_id: None,
        actor_id: None,
        role: None,
        tool_log_summary: None,
        tool_log_index: None,
        event_count: 0,
    };

    let mut tool_log_index_hash: Option<Vec<u8>> = None;
    let batch_size = 1000u64;
    let mut scanned_count = 0u64;

    loop {
        // Stop if we've scanned more than the limit (plus batch overhead)
        if scanned_count >= args.limit + batch_size {
            break;
        }

        let events = match ledger.read_from(cursor, batch_size) {
            Ok(events) => events,
            Err(e) => {
                return output_error(
                    json_output,
                    "ledger_error",
                    &format!("Failed to read ledger: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };

        if events.is_empty() {
            break;
        }

        for event in &events {
            scanned_count += 1;
            if let Some(episode_info) = extract_episode_info(event, &args.episode_id) {
                response.event_count += 1;

                // Update status based on event type
                match event.event_type.as_str() {
                    "episode_spawned" => {
                        response.status = "SPAWNED".to_string();
                        response.work_id = episode_info.work_id;
                        response.actor_id = Some(event.actor_id.clone());
                        response.role = episode_info.role;
                    },
                    "tool_executed" | "tool_decided" => {
                        response.status = "RUNNING".to_string();
                    },
                    "session_terminated" => {
                        response.status = "TERMINATED".to_string();
                        tool_log_index_hash = episode_info.tool_log_index_hash;
                    },
                    _ => {},
                }
            }
        }

        cursor = events.last().map_or(cursor, |e| e.seq_id.unwrap_or(0) + 1);
    }

    if response.event_count == 0 {
        return output_error(
            json_output,
            "not_found",
            &format!("No events found for episode_id: {}", args.episode_id),
            exit_codes::NOT_FOUND,
        );
    }

    // Try to load tool log index from CAS if we have a hash
    if let Some(hash) = tool_log_index_hash {
        if let Some(index) = load_tool_log_index_from_cas(cas_path, &hash) {
            response.tool_log_summary = Some(ToolLogSummary {
                total_executions: index.counts.total_executions,
                successful_executions: index.counts.successful_executions,
                failed_executions: index.counts.failed_executions,
                total_tokens: index.counts.total_tokens,
                total_bytes_io: index.counts.total_bytes_io,
                total_wall_ms: index.counts.total_wall_ms,
            });

            if args.full {
                response.tool_log_index = Some(index);
            }
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Episode Details");
        println!("  Episode ID:         {}", response.episode_id);
        println!("  Status:             {}", response.status);
        if let Some(work_id) = &response.work_id {
            println!("  Work ID:            {work_id}");
        }
        if let Some(actor) = &response.actor_id {
            println!("  Actor ID:           {actor}");
        }
        if let Some(role) = &response.role {
            println!("  Role:               {role}");
        }
        println!("  Events Found:       {}", response.event_count);

        if let Some(summary) = &response.tool_log_summary {
            println!();
            println!("Tool Log Summary");
            println!("  Total Executions:   {}", summary.total_executions);
            println!("  Successful:         {}", summary.successful_executions);
            println!("  Failed:             {}", summary.failed_executions);
            println!("  Total Tokens:       {}", summary.total_tokens);
            println!("  Total I/O Bytes:    {}", summary.total_bytes_io);
            println!("  Total Wall Time:    {} ms", summary.total_wall_ms);
        }

        if args.full {
            if let Some(index) = &response.tool_log_index {
                println!();
                println!("Tool Log Index (full)");
                println!("  Schema:             {}", index.schema);
                println!(
                    "  Receipt Count:      {}",
                    index.tool_execution_receipt_hashes.len()
                );
                println!("  First Sequence:     {}", index.first_sequence);
                println!("  Is Final Chunk:     {}", index.is_final_chunk);

                if !index.tool_execution_receipt_hashes.is_empty() {
                    println!();
                    println!("Receipt Hashes:");
                    for (i, hash) in index.tool_execution_receipt_hashes.iter().enumerate() {
                        println!("  [{i}] {hash}");
                    }
                }
            }
        }
    }

    exit_codes::SUCCESS
}

/// Extracted episode information from an event.
struct EpisodeInfo {
    work_id: Option<String>,
    role: Option<String>,
    tool_log_index_hash: Option<Vec<u8>>,
}

/// Extracts episode-related information from an event if it matches the
/// `episode_id`.
fn extract_episode_info(event: &EventRecord, episode_id: &str) -> Option<EpisodeInfo> {
    // Check session_id first (episodes often use session_id == episode_id)
    if event.session_id == episode_id {
        let payload: serde_json::Value = serde_json::from_slice(&event.payload).ok()?;
        return Some(EpisodeInfo {
            work_id: payload
                .get("work_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            role: payload
                .get("role")
                .and_then(|v| v.as_str())
                .map(String::from),
            tool_log_index_hash: payload
                .get("tool_log_index_hash")
                .and_then(|v| v.as_str())
                .and_then(|s| parse_cas_hash_32("tool_log_index_hash", s).ok())
                .map(|value| value.to_vec()),
        });
    }

    // Try payload check for episode_id field
    let payload: serde_json::Value = serde_json::from_slice(&event.payload).ok()?;
    let event_episode_id = payload.get("episode_id").and_then(|v| v.as_str())?;
    if event_episode_id != episode_id {
        return None;
    }

    Some(EpisodeInfo {
        work_id: payload
            .get("work_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        role: payload
            .get("role")
            .and_then(|v| v.as_str())
            .map(String::from),
        tool_log_index_hash: payload
            .get("tool_log_index_hash")
            .and_then(|v| v.as_str())
            .and_then(|s| parse_cas_hash_32("tool_log_index_hash", s).ok())
            .map(|value| value.to_vec()),
    })
}

/// Loads a tool log index from CAS by hash.
fn load_tool_log_index_from_cas(cas_path: &Path, hash: &[u8]) -> Option<ToolLogIndexV1> {
    if hash.len() != 32 {
        return None;
    }
    let hex_hash = hex::encode(hash);
    let (prefix, suffix) = hex_hash.split_at(4);
    let file_path = cas_path.join("objects").join(prefix).join(suffix);

    // SECURITY: Validate file size before reading to prevent DoS
    let metadata = std::fs::metadata(&file_path).ok()?;
    if metadata.len() > MAX_CAS_FILE_SIZE {
        return None;
    }

    let content = std::fs::read(&file_path).ok()?;

    // SECURITY: Verify hash using constant-time comparison
    let computed_hash = blake3::hash(&content);
    if !constant_time_hash_eq(computed_hash.as_bytes(), hash) {
        return None;
    }

    // Parse as JSON
    let index: ToolLogIndexV1 = serde_json::from_slice(&content).ok()?;

    // Validate schema
    if index.schema != TOOL_LOG_INDEX_V1_SCHEMA {
        return None;
    }

    Some(index)
}

// =============================================================================
// Receipt Show Command
// =============================================================================

/// Execute the receipt show command.
fn run_receipt_show(args: &ReceiptShowArgs, cas_path: &Path, json_output: bool) -> u8 {
    // Validate receipt hash
    if args.receipt_hash.is_empty() {
        return output_error(
            json_output,
            "invalid_hash",
            "Receipt hash cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Parse and normalize hash.
    let (file_path, hash_bytes) =
        match parse_cas_hash_to_path(cas_path, &args.receipt_hash, "receipt_hash") {
            Ok(value) => value,
            Err(CasHashParseError::InvalidHex { message, .. }) => {
                return output_error(
                    json_output,
                    "invalid_hash",
                    &format!("Invalid hex encoding: {message}"),
                    exit_codes::VALIDATION_ERROR,
                );
            },
            Err(CasHashParseError::InvalidLength {
                expected, actual, ..
            }) => {
                return output_error(
                    json_output,
                    "invalid_hash",
                    &format!("Receipt hash must be {expected} bytes, got {actual}"),
                    exit_codes::VALIDATION_ERROR,
                );
            },
        };
    let normalized_hash = hex::encode(hash_bytes);

    // SECURITY: Validate file size before reading to prevent DoS
    let metadata = match std::fs::metadata(&file_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return output_error(
                json_output,
                "not_found",
                &format!("Receipt not found in CAS: {}", args.receipt_hash),
                exit_codes::NOT_FOUND,
            );
        },
        Err(e) => {
            return output_error(
                json_output,
                "io_error",
                &format!("Failed to read CAS metadata: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    if metadata.len() > MAX_CAS_FILE_SIZE {
        return output_error(
            json_output,
            "file_too_large",
            &format!(
                "CAS file exceeds maximum size ({} bytes > {} bytes)",
                metadata.len(),
                MAX_CAS_FILE_SIZE
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    let content = match std::fs::read(&file_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return output_error(
                json_output,
                "not_found",
                &format!("Receipt not found in CAS: {}", args.receipt_hash),
                exit_codes::NOT_FOUND,
            );
        },
        Err(e) => {
            return output_error(
                json_output,
                "io_error",
                &format!("Failed to read CAS: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // SECURITY: Verify hash using constant-time comparison
    let computed_hash = blake3::hash(&content);
    if !constant_time_hash_eq(computed_hash.as_bytes(), &hash_bytes) {
        return output_error(
            json_output,
            "hash_mismatch",
            "CAS content hash mismatch (possible corruption)",
            exit_codes::GENERIC_ERROR,
        );
    }

    // Try to parse as JSON and detect receipt type
    let (receipt_type, parsed_content) = serde_json::from_slice::<serde_json::Value>(&content)
        .map_or_else(
            |_| {
                (
                    "binary".to_string(),
                    serde_json::Value::String(format!("<binary data, {} bytes>", content.len())),
                )
            },
            |json| {
                let receipt_type = detect_receipt_type(&json);
                (receipt_type, json)
            },
        );

    let response = ReceiptShowResponse {
        hash: normalized_hash,
        receipt_type,
        size_bytes: content.len() as u64,
        content: parsed_content,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Receipt Details");
        println!("  Hash:               {}", response.hash);
        println!("  Type:               {}", response.receipt_type);
        println!("  Size:               {} bytes", response.size_bytes);
        println!();
        println!("Content:");
        println!(
            "{}",
            serde_json::to_string_pretty(&response.content).unwrap_or_else(|_| "{}".to_string())
        );
    }

    exit_codes::SUCCESS
}

/// Known schema prefixes for receipt type detection.
///
/// Uses prefix matching (e.g., `apm2.gate_receipt.`) instead of substring
/// matching to prevent false positives with schema names like
/// `my_gate_receipt_v2`.
const RECEIPT_SCHEMA_PREFIXES: &[(&str, &str)] = &[
    ("apm2.gate_receipt.", "gate_receipt"),
    ("apm2.merge_receipt.", "merge_receipt"),
    ("apm2.review_receipt.", "review_receipt"),
    ("apm2.review_artifact.", "review_receipt"),
    ("apm2.projection.", "projection_receipt"),
];

/// Detects the receipt type from JSON content.
///
/// Uses exact matching against known schema constants first, then falls back to
/// prefix matching for extensibility. Avoids substring `.contains()` matching
/// which could produce false positives.
fn detect_receipt_type(json: &serde_json::Value) -> String {
    // Check for schema field
    if let Some(schema) = json.get("schema").and_then(|v| v.as_str()) {
        // First, check exact matches against known constants
        if schema == REVIEW_ARTIFACT_SCHEMA_IDENTIFIER {
            return "review_receipt".to_string();
        }
        if schema == SUMMARY_RECEIPT_SCHEMA {
            return "summary_receipt".to_string();
        }
        if schema == TOOL_LOG_INDEX_V1_SCHEMA {
            return "tool_log_index".to_string();
        }
        if schema == TOOL_EXECUTION_RECEIPT_SCHEMA {
            return "tool_execution_receipt".to_string();
        }
        if schema == PROJECTION_ARTIFACT_SCHEMA_IDENTIFIER {
            return "projection_receipt".to_string();
        }

        // Then, use prefix matching for types without defined constants
        for (prefix, receipt_type) in RECEIPT_SCHEMA_PREFIXES {
            if schema.starts_with(prefix) {
                return (*receipt_type).to_string();
            }
        }

        // Return the schema itself if no known match
        return schema.to_string();
    }

    // Fallback: Check for type-specific fields when schema is absent
    if json.get("verdict").is_some() && json.get("gate_id").is_some() {
        return "gate_receipt".to_string();
    }
    if json.get("review_verdict").is_some() {
        return "review_receipt".to_string();
    }
    if json.get("outcome").is_some() && json.get("summary_text").is_some() {
        return "summary_receipt".to_string();
    }

    "unknown".to_string()
}

// =============================================================================
// Receipt List Command (TCK-00560)
// =============================================================================

/// List receipt headers from the index.
///
/// Uses the receipt index for O(1) access instead of scanning the receipt
/// directory. Common operations no longer require full directory scans.
///
/// # Deterministic Ordering (TCK-00535)
///
/// Receipts are sorted by `timestamp_secs` descending (most recent first).
/// For equal timestamps, receipts are sorted by `content_hash` ascending
/// to ensure deterministic output across runs.
///
/// When `--since` is provided, only receipts with `timestamp_secs >= since`
/// are included.
fn run_receipt_list(args: &ReceiptListArgs, json_output: bool) -> u8 {
    let Some(apm2_home) = apm2_core::github::resolve_apm2_home() else {
        return output_error(
            json_output,
            "apm2_home_not_found",
            "Cannot resolve APM2_HOME for receipt store",
            exit_codes::GENERIC_ERROR,
        );
    };

    let receipts_dir = apm2_home.join("private").join("fac").join("receipts");
    let headers_result = apm2_core::fac::list_receipt_headers(&receipts_dir);
    let mut headers = headers_result.headers;

    // Deterministic ordering: timestamp descending, content_hash ascending
    // for equal timestamps. This ensures stable output across runs.
    headers.sort_by(|a, b| {
        b.timestamp_secs
            .cmp(&a.timestamp_secs)
            .then_with(|| a.content_hash.cmp(&b.content_hash))
    });

    let total_indexed = headers.len();

    // Apply --since filter if provided.
    let since_epoch = args.since;
    let filtered_headers: Vec<_> = if let Some(since) = since_epoch {
        headers
            .into_iter()
            .filter(|h| h.timestamp_secs >= since)
            .collect()
    } else {
        headers
    };

    let filtered_total = filtered_headers.len();
    let display_count = filtered_total.min(args.limit);
    let display_headers = &filtered_headers[..display_count];

    if json_output {
        let mut result = serde_json::json!({
            "status": "ok",
            "total_indexed": total_indexed,
            "displayed": display_count,
            "receipts": display_headers.iter().map(|h| {
                serde_json::json!({
                    "content_hash": h.content_hash,
                    "job_id": h.job_id,
                    "outcome": h.outcome,
                    "timestamp_secs": h.timestamp_secs,
                    "queue_lane": h.queue_lane,
                    "unsafe_direct": h.unsafe_direct,
                })
            }).collect::<Vec<_>>(),
        });
        if let Some(since) = since_epoch {
            result["since_epoch"] = serde_json::Value::Number(since.into());
            result["filtered_total"] = serde_json::Value::Number(filtered_total.into());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        let filter_note =
            since_epoch.map_or_else(String::new, |since| format!(" (since epoch {since})"));
        println!("Receipt Index ({total_indexed} total{filter_note}, showing {display_count})");
        println!();
        if display_headers.is_empty() {
            println!("  (no receipts indexed)");
        } else {
            println!(
                "  {:<12} {:<44} {:<12} Timestamp",
                "Job ID", "Content Hash", "Outcome"
            );
            println!("  {}", "-".repeat(80));
            for h in display_headers {
                println!(
                    "  {:<12} {:<44} {:<12} {}",
                    truncate_str(&h.job_id, 12),
                    truncate_str(&h.content_hash, 44),
                    format!("{:?}", h.outcome),
                    h.timestamp_secs,
                );
            }
        }
    }
    exit_codes::SUCCESS
}

/// Truncate a string to at most `max_len` characters, appending ".." if
/// truncated. Uses char-aware truncation to avoid panicking on multi-byte
/// UTF-8 boundaries.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else if max_len > 2 {
        let truncated: String = s.chars().take(max_len - 2).collect();
        format!("{truncated}..")
    } else {
        s.chars().take(max_len).collect()
    }
}

// =============================================================================
// Receipt Status Command (TCK-00560)
// =============================================================================

/// Look up the latest receipt for a job ID using the index.
///
/// Consults the receipt index first (O(1)), falls back to bounded directory
/// scan only if the index miss. This satisfies the ticket requirement:
/// "Common operations do not require full receipt directory scans."
fn run_receipt_status(args: &ReceiptStatusArgs, json_output: bool) -> u8 {
    if args.job_id.is_empty() {
        return output_error(
            json_output,
            "invalid_job_id",
            "Job ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    let Some(apm2_home) = apm2_core::github::resolve_apm2_home() else {
        return output_error(
            json_output,
            "apm2_home_not_found",
            "Cannot resolve APM2_HOME for receipt store",
            exit_codes::GENERIC_ERROR,
        );
    };

    let receipts_dir = apm2_home.join("private").join("fac").join("receipts");

    if let Some(receipt) = apm2_core::fac::lookup_job_receipt(&receipts_dir, &args.job_id) {
        if json_output {
            let result = serde_json::json!({
                "status": "found",
                "job_id": receipt.job_id,
                "content_hash": receipt.content_hash,
                "outcome": receipt.outcome,
                "timestamp_secs": receipt.timestamp_secs,
                "reason": receipt.reason,
                "unsafe_direct": receipt.unsafe_direct,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        } else {
            println!("Receipt for job {}", args.job_id);
            println!("  Content Hash:   {}", receipt.content_hash);
            println!("  Outcome:        {:?}", receipt.outcome);
            println!("  Timestamp:      {}", receipt.timestamp_secs);
            println!("  Reason:         {}", receipt.reason);
            println!("  Unsafe Direct:  {}", receipt.unsafe_direct);
        }
        exit_codes::SUCCESS
    } else {
        if json_output {
            let result = serde_json::json!({
                "status": "not_found",
                "job_id": args.job_id,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        } else {
            println!("No receipt found for job {}", args.job_id);
        }
        exit_codes::NOT_FOUND
    }
}

// =============================================================================
// Receipt Reindex Command (TCK-00560)
// =============================================================================

/// Execute the receipt reindex command.
///
/// Rebuilds the non-authoritative receipt index by scanning all receipt files
/// in the receipt store. The index is a cache for fast job/receipt lookup.
fn run_receipt_reindex(json_output: bool) -> u8 {
    let Some(apm2_home) = apm2_core::github::resolve_apm2_home() else {
        return output_error(
            json_output,
            "apm2_home_not_found",
            "Cannot resolve APM2_HOME for receipt store",
            exit_codes::GENERIC_ERROR,
        );
    };

    let receipts_dir = apm2_home.join("private").join("fac").join("receipts");

    if !receipts_dir.is_dir() {
        if json_output {
            let result = serde_json::json!({
                "status": "ok",
                "message": "no receipt directory found, nothing to index",
                "entries": 0,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        } else {
            println!(
                "no receipt directory found at {}, nothing to index",
                receipts_dir.display()
            );
        }
        return exit_codes::SUCCESS;
    }

    let start = std::time::Instant::now();
    match apm2_core::fac::ReceiptIndexV1::rebuild_from_store(&receipts_dir) {
        Ok(index) => {
            let count = index.len();
            match index.persist(&receipts_dir) {
                Ok(index_path) => {
                    let elapsed = start.elapsed();
                    if json_output {
                        let result = serde_json::json!({
                            "status": "ok",
                            "entries": count,
                            "index_path": index_path.display().to_string(),
                            "rebuild_epoch": index.rebuild_epoch,
                            "elapsed_ms": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&result).unwrap_or_default()
                        );
                    } else {
                        println!(
                            "receipt index rebuilt: {} entries in {:.2}s → {}",
                            count,
                            elapsed.as_secs_f64(),
                            index_path.display()
                        );
                    }
                    exit_codes::SUCCESS
                },
                Err(err) => output_error(
                    json_output,
                    "index_persist_failed",
                    &format!("failed to persist receipt index: {err}"),
                    exit_codes::GENERIC_ERROR,
                ),
            }
        },
        Err(err) => output_error(
            json_output,
            "index_rebuild_failed",
            &format!("failed to rebuild receipt index: {err}"),
            exit_codes::GENERIC_ERROR,
        ),
    }
}

// =============================================================================
// Receipt Verify Command (TCK-00576)
// =============================================================================

/// Verify a receipt's signed envelope.
///
/// Loads the signed receipt envelope for the given content hash (or from the
/// provided `.sig.json` file path) and verifies the Ed25519 signature against
/// the persistent broker key. Returns exit code 0 on success, non-zero on
/// verification failure.
fn run_receipt_verify(args: &ReceiptVerifyArgs, json_output: bool) -> u8 {
    let Some(apm2_home) = apm2_core::github::resolve_apm2_home() else {
        return output_error(
            json_output,
            "apm2_home_not_found",
            "Cannot resolve APM2_HOME for receipt store",
            exit_codes::GENERIC_ERROR,
        );
    };

    let fac_root = apm2_home.join("private").join("fac");
    let receipts_dir = fac_root.join("receipts");

    // Load signing key for verification.
    let signer = match crate::commands::fac_key_material::load_persistent_signer(&fac_root) {
        Ok(s) => s,
        Err(e) => {
            return output_error(
                json_output,
                "signing_key_not_found",
                &format!("Cannot load signing key for verification: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };
    let verifying_key = signer.verifying_key();

    // Determine whether the argument is a file path or a content hash.
    let input = &args.digest_or_path;
    let (envelope, content_hash) = if std::path::Path::new(input).is_file() {
        // Path mode: read the file directly.
        let data = match std::fs::read(input) {
            Ok(d) => d,
            Err(e) => {
                return output_error(
                    json_output,
                    "io_error",
                    &format!("Cannot read file {input}: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };
        match apm2_core::fac::deserialize_signed_envelope(&data) {
            Ok(env) => {
                let digest = env.payload_digest.clone();
                (env, digest)
            },
            Err(e) => {
                return output_error(
                    json_output,
                    "envelope_parse_error",
                    &format!("Cannot parse signed envelope: {e}"),
                    exit_codes::VALIDATION_ERROR,
                );
            },
        }
    } else {
        // Digest mode: normalize and load from receipts directory.
        let normalized = if input.starts_with("b3-256:") {
            input.clone()
        } else {
            format!("b3-256:{input}")
        };
        match apm2_core::fac::load_signed_envelope(&receipts_dir, &normalized) {
            Ok(env) => (env, normalized),
            Err(e) => {
                return output_error(
                    json_output,
                    "envelope_not_found",
                    &format!("Cannot load signed envelope for {input}: {e}"),
                    exit_codes::NOT_FOUND,
                );
            },
        }
    };

    // Verify the signature.
    match apm2_core::fac::verify_receipt_signature(&envelope, &content_hash, &verifying_key) {
        Ok(()) => {
            if json_output {
                let result = serde_json::json!({
                    "status": "ok",
                    "verified": true,
                    "payload_digest": envelope.payload_digest,
                    "signer_id": envelope.signer_id,
                    "signer_public_key_hex": envelope.signer_public_key_hex,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            } else {
                println!(
                    "receipt signature verified: digest={} signer={}",
                    envelope.payload_digest, envelope.signer_id
                );
            }
            exit_codes::SUCCESS
        },
        Err(e) => output_error(
            json_output,
            "verification_failed",
            &format!("Signature verification failed: {e}"),
            exit_codes::VALIDATION_ERROR,
        ),
    }
}

// =============================================================================
// Receipt Merge Command (TCK-00543)
// =============================================================================

/// Execute the receipt merge command: set-union merge with audit report.
fn run_receipt_merge(args: &ReceiptMergeArgs, json_output: bool) -> u8 {
    let source_dir = &args.from;
    let target_dir = &args.into;

    match apm2_core::fac::merge_receipt_dirs(source_dir, target_dir) {
        Ok(report) => {
            if json_output {
                let result = serde_json::json!({
                    "status": "ok",
                    "receipts_copied": report.receipts_copied,
                    "duplicates_skipped": report.duplicates_skipped,
                    "total_target_receipts": report.total_target_receipts,
                    "job_id_mismatches": report.job_id_mismatches,
                    "parse_failures": report.parse_failures,
                    "merged_headers": report.merged_headers,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            } else {
                println!(
                    "receipt merge: {} copied, {} duplicates skipped, {} total in target",
                    report.receipts_copied, report.duplicates_skipped, report.total_target_receipts,
                );

                if !report.job_id_mismatches.is_empty() {
                    println!(
                        "\nWARNING: {} job_id mismatch(es) detected (same digest, different job_id):",
                        report.job_id_mismatches.len()
                    );
                    for m in &report.job_id_mismatches {
                        println!(
                            "  digest={} source_job_id={} target_job_id={}",
                            m.content_hash, m.source_job_id, m.target_job_id
                        );
                    }
                }

                if !report.parse_failures.is_empty() {
                    println!("\n{} parse failure(s):", report.parse_failures.len());
                    for f in &report.parse_failures {
                        println!("  {}: {}", f.path, f.reason);
                    }
                }
            }
            exit_codes::SUCCESS
        },
        Err(e) => output_error(
            json_output,
            "merge_failed",
            &format!("Receipt merge failed: {e}"),
            exit_codes::GENERIC_ERROR,
        ),
    }
}

fn default_context_rebuild_output_dir(episode_id: &str) -> PathBuf {
    let apm2_home = std::env::var_os("APM2_HOME")
        .map(PathBuf::from)
        .filter(|value| !value.as_os_str().is_empty())
        .or_else(|| directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(".apm2")))
        .unwrap_or_else(|| PathBuf::from(".apm2-fallback"));
    apm2_home
        .join("private")
        .join("fac")
        .join("context_rebuild")
        .join(episode_id)
}

// =============================================================================
// Context Rebuild Command
// =============================================================================

/// Execute the context rebuild command.
fn run_context_rebuild(
    args: &ContextRebuildArgs,
    ledger_path: &Path,
    cas_path: &Path,
    json_output: bool,
) -> u8 {
    // Validate inputs
    if args.role.is_empty() {
        return output_error(
            json_output,
            "invalid_role",
            "Role cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_episode_id",
            "Episode ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Determine output directory
    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| default_context_rebuild_output_dir(&args.episode_id));

    // Create output directory with secure permissions.
    if let Err(e) = crate::commands::fac_permissions::ensure_dir_with_mode(&output_dir) {
        return output_error(
            json_output,
            "io_error",
            &format!("Failed to create output directory: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    // Open ledger
    let ledger = match open_ledger(ledger_path) {
        Ok(l) => l,
        Err(e) => {
            return output_error(
                json_output,
                "ledger_error",
                &format!("Failed to open ledger: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Calculate start cursor based on limit
    let mut cursor = match calculate_start_cursor(&ledger, args.limit) {
        Ok(c) => c,
        Err(e) => {
            return output_error(
                json_output,
                "ledger_error",
                &format!("Failed to query ledger head: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Find episode spawn event to get context pack hash
    let mut context_pack_hash: Option<Vec<u8>> = None;
    let mut artifacts_retrieved = 0u64;
    let batch_size = 1000u64;
    let mut scanned_count = 0u64;

    loop {
        // Stop if we've scanned more than the limit (plus batch overhead)
        if scanned_count >= args.limit + batch_size {
            break;
        }

        let events = match ledger.read_from(cursor, batch_size) {
            Ok(events) => events,
            Err(e) => {
                return output_error(
                    json_output,
                    "ledger_error",
                    &format!("Failed to read ledger: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };

        if events.is_empty() {
            break;
        }

        for event in &events {
            scanned_count += 1;
            if event.event_type == "episode_spawned" {
                if let Some(info) = extract_episode_info(event, &args.episode_id) {
                    // Check role matches
                    if info.role.as_deref() == Some(args.role.as_str()) {
                        // Extract context pack hash from payload
                        if let Ok(payload) =
                            serde_json::from_slice::<serde_json::Value>(&event.payload)
                        {
                            context_pack_hash = payload
                                .get("context_pack_hash")
                                .and_then(|v| v.as_str())
                                .and_then(|s| parse_cas_hash_32("context_pack_hash", s).ok())
                                .map(|value| value.to_vec());
                        }
                        break;
                    }
                }
            }
        }

        if context_pack_hash.is_some() {
            break;
        }

        cursor = events.last().map_or(cursor, |e| e.seq_id.unwrap_or(0) + 1);
    }

    let Some(context_pack_hash) = context_pack_hash else {
        return output_error(
            json_output,
            "not_found",
            &format!(
                "No episode_spawned event found for episode {} with role {}",
                args.episode_id, args.role
            ),
            exit_codes::NOT_FOUND,
        );
    };

    // Load context pack from CAS
    let hex_hash = hex::encode(&context_pack_hash);
    let (prefix, suffix) = hex_hash.split_at(4);
    let pack_path = cas_path.join("objects").join(prefix).join(suffix);

    // SECURITY: Validate file size before reading to prevent DoS
    let metadata = match std::fs::metadata(&pack_path) {
        Ok(m) => m,
        Err(e) => {
            return output_error(
                json_output,
                "cas_error",
                &format!("Failed to read context pack metadata: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    if metadata.len() > MAX_CAS_FILE_SIZE {
        return output_error(
            json_output,
            "file_too_large",
            &format!(
                "Context pack exceeds maximum size ({} bytes > {} bytes)",
                metadata.len(),
                MAX_CAS_FILE_SIZE
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    let pack_content = match std::fs::read(&pack_path) {
        Ok(c) => c,
        Err(e) => {
            return output_error(
                json_output,
                "cas_error",
                &format!("Failed to read context pack from CAS: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // SECURITY: Verify hash using constant-time comparison
    let computed_hash = blake3::hash(&pack_content);
    let deterministic = constant_time_hash_eq(computed_hash.as_bytes(), &context_pack_hash);

    // Write context pack to output directory
    let pack_output_path = output_dir.join("context_pack.json");
    if let Err(e) = std::fs::write(&pack_output_path, &pack_content) {
        return output_error(
            json_output,
            "io_error",
            &format!("Failed to write context pack: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }
    artifacts_retrieved += 1;

    // Try to parse and extract referenced artifacts
    if let Ok(pack_json) = serde_json::from_slice::<serde_json::Value>(&pack_content) {
        // Extract artifact hashes and retrieve them
        if let Some(artifacts) = pack_json.get("artifacts").and_then(|v| v.as_array()) {
            for artifact in artifacts {
                if let Some(hash_str) = artifact.get("hash").and_then(|v| v.as_str()) {
                    if let Ok(artifact_hash) = parse_cas_hash_32("artifact_hash", hash_str) {
                        if retrieve_artifact_to_dir(cas_path, &artifact_hash, &output_dir).is_ok() {
                            artifacts_retrieved += 1;
                        }
                    }
                }
            }
        }
    }

    let response = ContextRebuildResponse {
        role: args.role.clone(),
        episode_id: args.episode_id.clone(),
        output_dir: output_dir.display().to_string(),
        context_pack_hash: hex_hash,
        artifacts_retrieved,
        deterministic,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Context Rebuild Results");
        println!("  Role:               {}", response.role);
        println!("  Episode ID:         {}", response.episode_id);
        println!("  Output Directory:   {}", response.output_dir);
        println!("  Context Pack Hash:  {}", response.context_pack_hash);
        println!("  Artifacts Retrieved: {}", response.artifacts_retrieved);
        println!(
            "  Deterministic:      {}",
            if response.deterministic { "yes" } else { "no" }
        );
    }

    exit_codes::SUCCESS
}

/// Retrieves an artifact from CAS to the output directory.
///
/// # Security
///
/// Validates file size before copying to prevent `DoS` via large artifacts.
fn retrieve_artifact_to_dir(
    cas_path: &Path,
    hash: &[u8],
    output_dir: &Path,
) -> Result<(), std::io::Error> {
    if hash.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("artifact hash must be 32 bytes, got {}", hash.len()),
        ));
    }
    let hex_hash = hex::encode(hash);
    let (prefix, suffix) = hex_hash.split_at(4);
    let src_path = cas_path.join("objects").join(prefix).join(suffix);
    let dst_path = output_dir.join(&hex_hash);

    // SECURITY: Validate file size before copying to prevent DoS
    let metadata = std::fs::metadata(&src_path)?;
    if metadata.len() > MAX_CAS_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Artifact exceeds maximum size ({} bytes > {} bytes)",
                metadata.len(),
                MAX_CAS_FILE_SIZE
            ),
        ));
    }

    std::fs::copy(&src_path, &dst_path)?;
    Ok(())
}

// =============================================================================
// Lane Status Command (TCK-00515)
// =============================================================================

/// JSON response for `apm2 fac lane status`.
#[derive(Debug, Clone, Serialize)]
struct LaneStatusResponse {
    /// All lane statuses.
    lanes: Vec<LaneStatusV1>,
    /// Total number of lanes.
    total: usize,
    /// Number of lanes in each state.
    summary: LaneStateSummary,
}

/// Summary counts by lane state.
#[derive(Debug, Clone, Serialize)]
struct LaneStateSummary {
    idle: usize,
    leased: usize,
    running: usize,
    cleanup: usize,
    corrupt: usize,
}

/// Execute `apm2 fac lane status`.
///
/// Reports lane states derived from lock state + lease record + PID liveness.
/// Supports human-readable and JSON output modes.
fn run_lane_status(args: &LaneStatusArgs, json_output: bool) -> u8 {
    let manager = match LaneManager::from_default_home() {
        Ok(m) => m,
        Err(e) => {
            return output_error(
                json_output,
                "lane_error",
                &format!("Failed to initialize lane manager: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Ensure directories exist so status queries don't fail on fresh installs
    if let Err(e) = manager.ensure_directories() {
        return output_error(
            json_output,
            "lane_error",
            &format!("Failed to ensure lane directories: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    let statuses = match manager.all_lane_statuses() {
        Ok(s) => s,
        Err(e) => {
            return output_error(
                json_output,
                "lane_error",
                &format!("Failed to query lane statuses: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Apply state filter if provided
    let filtered: Vec<&LaneStatusV1> = if let Some(ref state_filter) = args.state {
        let target_state = match state_filter.to_uppercase().as_str() {
            "IDLE" => LaneState::Idle,
            "LEASED" => LaneState::Leased,
            "RUNNING" => LaneState::Running,
            "CLEANUP" => LaneState::Cleanup,
            "CORRUPT" => LaneState::Corrupt,
            other => {
                return output_error(
                    json_output,
                    "invalid_state_filter",
                    &format!(
                        "Unknown lane state: {other}. \
                         Valid states: IDLE, LEASED, RUNNING, CLEANUP, CORRUPT"
                    ),
                    exit_codes::VALIDATION_ERROR,
                );
            },
        };
        statuses
            .iter()
            .filter(|s| s.state == target_state)
            .collect()
    } else {
        statuses.iter().collect()
    };

    // Build summary counts from filtered set.
    let summary = LaneStateSummary {
        idle: filtered
            .iter()
            .filter(|s| s.state == LaneState::Idle)
            .count(),
        leased: filtered
            .iter()
            .filter(|s| s.state == LaneState::Leased)
            .count(),
        running: filtered
            .iter()
            .filter(|s| s.state == LaneState::Running)
            .count(),
        cleanup: filtered
            .iter()
            .filter(|s| s.state == LaneState::Cleanup)
            .count(),
        corrupt: filtered
            .iter()
            .filter(|s| s.state == LaneState::Corrupt)
            .count(),
    };
    let filtered_count =
        summary.idle + summary.leased + summary.running + summary.cleanup + summary.corrupt;

    let response = LaneStatusResponse {
        lanes: filtered.into_iter().cloned().collect(),
        total: filtered_count,
        summary,
    };
    match serde_json::to_string_pretty(&response) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            return output_error(
                json_output,
                "serialization_error",
                &format!("Failed to serialize lane status: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    }

    exit_codes::SUCCESS
}

// =============================================================================
// Lane Mark-Corrupt Command (TCK-00570)
// =============================================================================

/// Execute `apm2 fac lane mark-corrupt <lane_id> --reason ...`.
///
/// Operator workflow: manually mark a lane as CORRUPT with a reason string.
/// The lane refuses all future job leases until an operator clears the marker
/// via `apm2 fac doctor --fix`.
///
/// # State Machine
///
/// - Any state except RUNNING: writes `corrupt.v1.json` marker.
/// - Already CORRUPT: returns an error (marker already exists).
/// - RUNNING: returns an error (stop work and run `apm2 fac doctor --fix`).
///
/// # Security
///
/// - Exclusive lane lock is held for the entire operation.
/// - Marker is written via atomic write (temp + rename).
/// - Reason and `receipt_digest` are validated for length bounds.
fn run_lane_mark_corrupt(args: &LaneMarkCorruptArgs, json_output: bool) -> u8 {
    let manager = match LaneManager::from_default_home() {
        Ok(m) => m,
        Err(e) => {
            return output_error(
                json_output,
                "lane_error",
                &format!("Failed to initialize lane manager: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };
    run_lane_mark_corrupt_with_manager(&manager, args, json_output)
}

fn run_lane_mark_corrupt_with_manager(
    manager: &LaneManager,
    args: &LaneMarkCorruptArgs,
    json_output: bool,
) -> u8 {
    // Ensure directories exist (idempotent).
    if let Err(e) = manager.ensure_directories() {
        return output_error(
            json_output,
            "lane_error",
            &format!("Failed to ensure lane directories: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    // Acquire exclusive lock before any status reads or mutations.
    let _lock_guard = match manager.acquire_lock(&args.lane_id) {
        Ok(guard) => guard,
        Err(e) => {
            return output_error(
                json_output,
                "lane_error",
                &format!("Failed to acquire lock for lane {}: {e}", args.lane_id),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Query current lane status under lock.
    let status = match manager.lane_status(&args.lane_id) {
        Ok(s) => s,
        Err(e) => {
            return output_error(
                json_output,
                "lane_error",
                &format!("Failed to query lane status: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Refuse to mark a RUNNING lane.
    if status.state == LaneState::Running {
        return output_error(
            json_output,
            "lane_running",
            &format!(
                "Lane {} is RUNNING (pid={}). Stop active work first, then run `apm2 fac doctor --fix`.",
                args.lane_id,
                status.pid.unwrap_or(0)
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Refuse if already CORRUPT -- marker already exists.
    if status.state == LaneState::Corrupt {
        return output_error(
            json_output,
            "already_corrupt",
            &format!(
                "Lane {} is already CORRUPT (reason: {}). Run `apm2 fac doctor --fix` to reconcile.",
                args.lane_id,
                status.corrupt_reason.as_deref().unwrap_or("unknown")
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Validate reason length against MAX_STRING_LENGTH (512).
    if args.reason.len() > apm2_core::fac::lane::MAX_STRING_LENGTH {
        return output_error(
            json_output,
            "validation_error",
            &format!(
                "Reason exceeds maximum length ({} > {})",
                args.reason.len(),
                apm2_core::fac::lane::MAX_STRING_LENGTH,
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Validate optional receipt_digest format (b3-256:<64 lowercase hex>).
    if let Some(ref digest) = args.receipt_digest {
        if let Err(e) = apm2_core::fac::lane::validate_b3_256_digest("receipt_digest", digest) {
            return output_error(
                json_output,
                "validation_error",
                &format!("Invalid receipt digest: {e}"),
                exit_codes::VALIDATION_ERROR,
            );
        }
    }

    // Persist the corrupt marker via LaneManager, which generates the
    // detected_at timestamp internally as ISO-8601 (CTR-2501) and returns
    // it on success — no fragile load-back round-trip needed.
    let detected_at =
        match manager.mark_corrupt(&args.lane_id, &args.reason, args.receipt_digest.as_deref()) {
            Ok(ts) => ts,
            Err(e) => {
                return output_error(
                    json_output,
                    "persist_error",
                    &format!(
                        "Failed to persist corrupt marker for lane {}: {e}",
                        args.lane_id
                    ),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };

    let response = serde_json::json!({
        "lane_id": args.lane_id,
        "status": "CORRUPT",
        "reason": args.reason,
        "cleanup_receipt_digest": args.receipt_digest,
        "detected_at": detected_at,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_default()
    );

    if !json_output {
        eprintln!(
            "Lane {} marked as CORRUPT. Run `apm2 fac doctor --fix` to reconcile.",
            args.lane_id
        );
    }

    exit_codes::SUCCESS
}

// =============================================================================
// Lane Init Command (TCK-00539)
// =============================================================================

/// Execute `apm2 fac lane init`.
///
/// Creates all configured lane directories and writes default profiles.
/// Existing profiles are left untouched (idempotent). Emits a receipt
/// recording lanes created vs already existing.
fn run_lane_init(_args: &LaneInitArgs, json_output: bool) -> u8 {
    let manager = match LaneManager::from_default_home() {
        Ok(m) => m,
        Err(e) => {
            return output_error(
                json_output,
                "lane_error",
                &format!("Failed to initialize lane manager: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let receipt = match manager.init_lanes() {
        Ok(r) => r,
        Err(e) => {
            return output_error(
                json_output,
                "lane_init_error",
                &format!("Lane init failed: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    if json_output {
        match serde_json::to_string_pretty(&receipt) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                return output_error(
                    json_output,
                    "serialization_error",
                    &format!("Failed to serialize init receipt: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        }
    } else {
        print_lane_init_receipt(&receipt);
    }

    exit_codes::SUCCESS
}

/// Print a human-readable init receipt.
fn print_lane_init_receipt(receipt: &LaneInitReceiptV1) {
    println!("Lane pool initialized ({} lanes)", receipt.lane_count);
    println!();
    println!("  Node fingerprint: {}", receipt.node_fingerprint);
    println!("  Boundary ID:      {}", receipt.boundary_id);
    println!();

    if !receipt.lanes_created.is_empty() {
        println!("  Created:");
        for entry in &receipt.profiles {
            if entry.created {
                println!("    {:<12} {}", entry.lane_id, entry.profile_hash);
            }
        }
    }

    if !receipt.lanes_existing.is_empty() {
        println!("  Already existing:");
        for entry in &receipt.profiles {
            if !entry.created {
                println!("    {:<12} {}", entry.lane_id, entry.profile_hash);
            }
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Constant-time comparison for BLAKE3 hashes to prevent timing attacks.
///
/// # Security
///
/// Uses the `subtle` crate's `ConstantTimeEq` trait to perform comparison
/// in constant time, preventing timing side-channel attacks that could
/// leak information about the expected hash value.
#[inline]
fn constant_time_hash_eq(computed: &[u8], expected: &[u8]) -> bool {
    // If lengths differ, we still need constant-time behavior
    if computed.len() != expected.len() {
        return false;
    }
    bool::from(computed.ct_eq(expected))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CasHashParseError {
    InvalidHex {
        field: &'static str,
        message: String,
    },
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

fn parse_cas_hash_32(field: &'static str, hash_hex: &str) -> Result<[u8; 32], CasHashParseError> {
    let decoded = hex::decode(hash_hex.trim()).map_err(|err| CasHashParseError::InvalidHex {
        field,
        message: err.to_string(),
    })?;
    if decoded.len() != 32 {
        return Err(CasHashParseError::InvalidLength {
            field,
            expected: 32,
            actual: decoded.len(),
        });
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn parse_cas_hash_to_path(
    cas_path: &Path,
    hash_hex: &str,
    field: &'static str,
) -> Result<(PathBuf, [u8; 32]), CasHashParseError> {
    let hash_bytes = parse_cas_hash_32(field, hash_hex)?;
    let normalized_hex = hex::encode(hash_bytes);
    let (prefix, suffix) = normalized_hex.split_at(4);
    Ok((
        cas_path.join("objects").join(prefix).join(suffix),
        hash_bytes,
    ))
}

fn derive_fac_repo_or_exit(json_output: bool) -> Result<String, u8> {
    fac_review::derive_repo().map_err(|err| {
        output_error(
            json_output,
            "fac_repo_derivation_failed",
            &format!("failed to derive repository from git origin: {err}"),
            exit_codes::GENERIC_ERROR,
        )
    })
}

/// Output an error as pretty-printed JSON to stdout.
///
/// TCK-00606 S12: FAC commands are JSON-only. The `json_output` parameter
/// is retained for call-site compatibility but is always `true` at runtime.
fn output_error(_json_output: bool, code: &str, message: &str, exit_code: u8) -> u8 {
    let error = ErrorResponse {
        error: code.to_string(),
        message: message.to_string(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&error).unwrap_or_else(|_| {
            "{\"error\":\"serialization_failure\",\"message\":\"failed to serialize error response\"}"
                .to_string()
        })
    );
    exit_code
}

/// Output protocol errors in CLI-friendly format.
fn handle_protocol_error(json_output: bool, error: &ProtocolClientError) -> u8 {
    let exit_code = map_protocol_error(error);
    let (code, message) = match error {
        ProtocolClientError::DaemonNotRunning => (
            "daemon_not_running".to_string(),
            "Daemon is not running. Start with: apm2 daemon".to_string(),
        ),
        ProtocolClientError::ConnectionFailed(msg) => (
            "connection_failed".to_string(),
            format!("Failed to connect to daemon: {msg}"),
        ),
        ProtocolClientError::HandshakeFailed(msg) => (
            "handshake_failed".to_string(),
            format!("Protocol handshake failed: {msg}"),
        ),
        ProtocolClientError::DaemonError { code, message } => {
            (format!("daemon_{}", code.to_lowercase()), message.clone())
        },
        other => ("protocol_error".to_string(), other.to_string()),
    };

    output_error(json_output, &code, &message, exit_code)
}

// =============================================================================
// Verify Containment (TCK-00548)
// =============================================================================

/// Runs the `apm2 fac verify containment` command.
fn run_verify_containment(args: &ContainmentArgs, json_output: bool) -> u8 {
    let use_json = json_output || args.json;
    let pid = args.pid.unwrap_or_else(std::process::id);

    let verdict = match apm2_core::fac::verify_containment(pid, args.sccache_enabled) {
        Ok(v) => v,
        Err(e) => {
            if use_json {
                let err_json = serde_json::json!({
                    "error": e.to_string(),
                    "contained": false,
                    "pid": pid,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&err_json).unwrap_or_default()
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "error": e.to_string(),
                        "contained": false,
                        "pid": pid,
                    }))
                    .unwrap_or_default()
                );
            }
            return exit_codes::GENERIC_ERROR;
        },
    };

    if use_json {
        match serde_json::to_string_pretty(&verdict) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "error": "fac_verify_containment_serialization_failed",
                        "message": e.to_string(),
                    }))
                    .unwrap_or_default()
                );
                return exit_codes::GENERIC_ERROR;
            },
        }
    } else {
        if verdict.contained {
            println!(
                "PASS: all {} child process(es) contained in cgroup '{}'",
                verdict.processes_checked, verdict.reference_cgroup
            );
        } else {
            println!(
                "FAIL: {} mismatch(es) out of {} child process(es)",
                verdict.mismatches.len(),
                verdict.processes_checked
            );
            println!("  reference cgroup: {}", verdict.reference_cgroup);
            for m in &verdict.mismatches {
                println!(
                    "  PID {} ({}): expected '{}', actual '{}'",
                    m.pid, m.process_name, m.expected_cgroup, m.actual_cgroup
                );
            }
        }

        if verdict.sccache_detected {
            println!("  sccache process detected: yes");
        }
        if verdict.sccache_auto_disabled {
            if let Some(reason) = &verdict.sccache_disabled_reason {
                println!("  sccache auto-disabled: {reason}");
            }
        }

        println!(
            "  critical processes found: {}",
            verdict.critical_processes_found
        );
    }

    if verdict.contained {
        exit_codes::SUCCESS
    } else {
        exit_codes::VALIDATION_ERROR
    }
}

// =============================================================================
// Bundle Export/Import (TCK-00527)
// =============================================================================

/// Maximum envelope file size for bounded reads during import (256 KiB).
const MAX_BUNDLE_ENVELOPE_FILE_SIZE: u64 = 262_144;
/// Maximum manifest file size for bounded reads during import (64 KiB).
const MAX_BUNDLE_MANIFEST_FILE_SIZE: u64 =
    apm2_core::fac::evidence_bundle::MAX_MANIFEST_SIZE as u64;

/// Parse a hex-encoded digest string (with optional `b3-256:` prefix) into a
/// verified 32-byte array, or return `MalformedPolicyDigest` on any failure.
fn parse_verified_digest(
    field_name: &str,
    raw: &str,
) -> Result<[u8; 32], apm2_core::fac::evidence_bundle::EvidenceBundleError> {
    let hex_part = raw.strip_prefix("b3-256:").unwrap_or(raw);
    let bytes = hex::decode(hex_part).map_err(|e| {
        apm2_core::fac::evidence_bundle::EvidenceBundleError::MalformedPolicyDigest {
            field: field_name.to_string(),
            detail: format!("hex decode failed: {e}"),
        }
    })?;
    <[u8; 32]>::try_from(bytes).map_err(|v| {
        apm2_core::fac::evidence_bundle::EvidenceBundleError::MalformedPolicyDigest {
            field: field_name.to_string(),
            detail: format!("expected 32 bytes, got {}", v.len()),
        }
    })
}

/// Build a `BundleExportConfig` from authoritative receipt artifacts.
///
/// Constructs well-formed RFC-0028 and RFC-0029 boundary substructures so
/// that exported envelopes satisfy `import_evidence_bundle` validation.
///
/// # Errors
///
/// Returns `EvidenceBundleError::MalformedPolicyDigest` if `policy_hash` or
/// `canonicalizer_tuple_digest` is present but cannot be decoded to a valid
/// 32-byte digest. Fail-closed: export must not proceed with fabricated
/// placeholder digests.
fn build_export_config_from_receipt(
    receipt: &apm2_core::fac::FacJobReceiptV1,
) -> Result<
    apm2_core::fac::evidence_bundle::BundleExportConfig,
    apm2_core::fac::evidence_bundle::EvidenceBundleError,
> {
    use apm2_core::channel::BoundaryFlowPolicyBinding;

    // Derive policy binding from receipt traces. For local export the receipt
    // itself is the authoritative source — the policy/canonicalizer digests
    // are self-consistent (matching) to pass import validation.
    //
    // Fail-closed: if either digest field is present but malformed, reject
    // the export rather than fabricating a placeholder.
    let policy_binding = {
        let policy_digest = match receipt.policy_hash.as_deref() {
            Some(h) => parse_verified_digest("policy_hash", h)?,
            None => {
                return Err(
                    apm2_core::fac::evidence_bundle::EvidenceBundleError::MalformedPolicyDigest {
                        field: "policy_hash".to_string(),
                        detail: "field is absent; cannot construct policy binding without a verified digest".to_string(),
                    },
                );
            },
        };
        let canonicalizer_digest = match receipt.canonicalizer_tuple_digest.as_deref() {
            Some(h) => parse_verified_digest("canonicalizer_tuple_digest", h)?,
            None => {
                return Err(
                    apm2_core::fac::evidence_bundle::EvidenceBundleError::MalformedPolicyDigest {
                        field: "canonicalizer_tuple_digest".to_string(),
                        detail: "field is absent; cannot construct policy binding without a verified digest".to_string(),
                    },
                );
            },
        };

        Some(BoundaryFlowPolicyBinding {
            policy_digest,
            admitted_policy_root_digest: policy_digest,
            canonicalizer_tuple_digest: canonicalizer_digest,
            admitted_canonicalizer_tuple_digest: canonicalizer_digest,
        })
    };

    // Export only evidence that actually exists in the source receipt.
    // Leakage budget receipt, timing channel budget, and disclosure policy
    // binding are NOT present in FacJobReceiptV1 so they are honestly marked
    // absent (None). The envelope validation is aware of which fields are
    // present vs absent and does not require fabricated data.
    let leakage_budget_receipt = None;
    let timing_channel_budget = None;
    let disclosure_policy_binding = None;

    Ok(apm2_core::fac::evidence_bundle::BundleExportConfig {
        policy_binding,
        leakage_budget_receipt,
        timing_channel_budget,
        disclosure_policy_binding,
        // TCK-00555: Leakage budget policy defaults to Tier2 (fail-closed).
        // Tier0 requires explicit opt-in configuration. The secure default
        // bounds evidence export to 4 MiB / 16 classes / 64 leakage bits.
        leakage_budget_policy: Some(
            apm2_core::fac::evidence_bundle::LeakageBudgetPolicy::tier2_default(),
        ),
        // No declassification receipt by default — exports that exceed the
        // policy ceiling will fail closed.
        declassification_receipt: None,
    })
}

/// Discover receipt blob hash from the `content_hash` field and export it.
///
/// Returns the list of exported blob ref strings (hex-encoded BLAKE3 hashes).
///
/// # Errors
///
/// Returns `EvidenceBundleError::BlobExportFailed` if a referenced blob
/// cannot be decoded, retrieved from the store, or written to the output
/// directory. Fail-closed: export must not succeed when referenced blob
/// artifacts are missing or cannot be persisted.
fn discover_and_export_blobs(
    fac_root: &std::path::Path,
    receipt: &apm2_core::fac::FacJobReceiptV1,
    output_dir: &std::path::Path,
) -> Result<Vec<String>, apm2_core::fac::evidence_bundle::EvidenceBundleError> {
    let blob_store = apm2_core::fac::BlobStore::new(fac_root);
    let mut exported_refs = Vec::new();

    // Helper: parse hex, retrieve from store, write to output dir.
    let export_one_blob =
        |label: &str,
         raw_hash: &str|
         -> Result<String, apm2_core::fac::evidence_bundle::EvidenceBundleError> {
            let hex_part = raw_hash.strip_prefix("b3-256:").unwrap_or(raw_hash);
            let hash_bytes = hex::decode(hex_part).map_err(|e| {
                apm2_core::fac::evidence_bundle::EvidenceBundleError::BlobExportFailed {
                    blob_ref: raw_hash.to_string(),
                    detail: format!("{label}: hex decode failed: {e}"),
                }
            })?;
            let hash_arr = <[u8; 32]>::try_from(hash_bytes).map_err(|v| {
                apm2_core::fac::evidence_bundle::EvidenceBundleError::BlobExportFailed {
                    blob_ref: raw_hash.to_string(),
                    detail: format!("{label}: expected 32 bytes, got {}", v.len()),
                }
            })?;
            let blob_data = blob_store.retrieve(&hash_arr).map_err(|e| {
                apm2_core::fac::evidence_bundle::EvidenceBundleError::BlobExportFailed {
                    blob_ref: raw_hash.to_string(),
                    detail: format!("{label}: blob store retrieve failed: {e}"),
                }
            })?;
            let blob_filename = format!("{hex_part}.blob");
            let blob_dest = output_dir.join(&blob_filename);
            // MINOR security fix: use FAC-safe file write (0600 mode,
            // O_NOFOLLOW, symlink check) instead of std::fs::write.
            crate::commands::fac_permissions::write_fac_file_with_mode(&blob_dest, &blob_data)
                .map_err(|e| {
                    apm2_core::fac::evidence_bundle::EvidenceBundleError::BlobExportFailed {
                        blob_ref: raw_hash.to_string(),
                        detail: format!("{label}: write to {}: {e}", blob_dest.display()),
                    }
                })?;
            Ok(format!("b3-256:{hex_part}"))
        };

    // The receipt content_hash is a BLAKE3 hex digest — parse it to look
    // up the receipt blob in the content-addressed store.
    exported_refs.push(export_one_blob("content_hash", &receipt.content_hash)?);

    // Also export the job_spec_digest blob.
    exported_refs.push(export_one_blob(
        "job_spec_digest",
        &receipt.job_spec_digest,
    )?);

    Ok(exported_refs)
}

/// Validate that a job ID is safe for use as a filesystem path component.
///
/// Rejects empty strings, absolute paths, path separators, `..` components,
/// and any characters outside `[A-Za-z0-9_-]`. This prevents path traversal
/// attacks where a crafted `job_id` like `../../../etc/passwd` or `/tmp/evil`
/// could escape the FAC root directory.
fn validate_job_id_for_path(job_id: &str) -> Result<(), String> {
    if job_id.is_empty() {
        return Err("job_id must not be empty".to_string());
    }
    if job_id.starts_with('/') || job_id.starts_with('\\') {
        return Err(format!(
            "job_id must not be an absolute path, got {job_id:?}"
        ));
    }
    if job_id.contains("..") {
        return Err(format!(
            "job_id must not contain path traversal (..), got {job_id:?}"
        ));
    }
    if !job_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
    {
        return Err(format!(
            "job_id contains invalid characters: only [A-Za-z0-9._-] allowed, got {job_id:?}"
        ));
    }
    Ok(())
}

/// Runs `apm2 fac bundle export <job_id>`.
fn run_bundle_export(args: &BundleExportArgs, json_output: bool) -> u8 {
    // MAJOR security fix: validate job_id before using as path component.
    // Untrusted job_id from job receipts could contain path traversal sequences
    // (e.g., "../../../etc/passwd" or "/tmp/evil") that escape the FAC root.
    if let Err(reason) = validate_job_id_for_path(&args.job_id) {
        return output_error(
            json_output,
            "fac_bundle_export_invalid_job_id",
            &reason,
            exit_codes::VALIDATION_ERROR,
        );
    }

    let fac_root =
        apm2_core::github::resolve_apm2_home().map(|home| home.join("private").join("fac"));

    let Some(fac_root) = fac_root else {
        return output_error(
            json_output,
            "fac_home_not_resolved",
            "cannot resolve $APM2_HOME for FAC root",
            exit_codes::GENERIC_ERROR,
        );
    };

    let receipts_dir = fac_root.join("receipts");

    // Look up the job receipt.
    let Some(receipt) = apm2_core::fac::lookup_job_receipt(&receipts_dir, &args.job_id) else {
        return output_error(
            json_output,
            "fac_bundle_receipt_not_found",
            &format!("no receipt found for job_id={}", args.job_id),
            exit_codes::NOT_FOUND,
        );
    };

    // Determine output directory (create early so blobs can be exported into it).
    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| fac_root.join("bundles").join(&args.job_id));

    // MINOR security fix: use FAC-safe permissions helper (0700 directories)
    // instead of std::fs::create_dir_all which inherits the default umask and
    // follows symlinks.
    if let Err(e) = crate::commands::fac_permissions::ensure_dir_with_mode(&output_dir) {
        return output_error(
            json_output,
            "fac_bundle_export_mkdir_failed",
            &format!(
                "cannot create export directory {}: {e}",
                output_dir.display()
            ),
            exit_codes::GENERIC_ERROR,
        );
    }

    // Discover and export blobs (receipt + job spec) to the output directory.
    // Fail-closed: if any referenced blob cannot be retrieved or written, the
    // command fails rather than producing an incomplete bundle.
    let blob_refs = match discover_and_export_blobs(&fac_root, &receipt, &output_dir) {
        Ok(refs) => refs,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_blob_export_failed",
                &format!("blob export failed: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Build the envelope with authoritative export config constructed from
    // the receipt (satisfies import validation). Fail-closed: if policy/
    // canonicalizer digests cannot be parsed to verified 32-byte arrays, the
    // command fails rather than fabricating placeholder digests.
    let config = match build_export_config_from_receipt(&receipt) {
        Ok(c) => c,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_export_malformed_digest",
                &format!("failed to construct export config: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };
    let envelope = match apm2_core::fac::evidence_bundle::build_evidence_bundle_envelope(
        &receipt, &config, &blob_refs,
    ) {
        Ok(env) => env,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_export_failed",
                &format!("failed to build evidence bundle: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let manifest =
        match apm2_core::fac::evidence_bundle::build_evidence_bundle_manifest(&envelope, &[]) {
            Ok(manifest) => manifest,
            Err(e) => {
                return output_error(
                    json_output,
                    "fac_bundle_manifest_build_failed",
                    &format!("bundle manifest build failed: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };

    // Serialize and write the envelope + manifest.
    let envelope_data = match apm2_core::fac::evidence_bundle::serialize_envelope(&envelope) {
        Ok(d) => d,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_export_serialize_failed",
                &format!("failed to serialize envelope: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };
    let manifest_data = match apm2_core::fac::evidence_bundle::serialize_manifest(&manifest) {
        Ok(d) => d,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_manifest_serialize_failed",
                &format!("bundle manifest serialize failed: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // MINOR security fix: use FAC-safe file write (0600 mode, O_NOFOLLOW,
    // symlink check) instead of std::fs::write which inherits default umask
    // and follows symlinks.
    let envelope_path = output_dir.join("envelope.json");
    if let Err(e) =
        crate::commands::fac_permissions::write_fac_file_with_mode(&envelope_path, &envelope_data)
    {
        return output_error(
            json_output,
            "fac_bundle_export_write_failed",
            &format!("failed to write envelope: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }
    let manifest_path = output_dir.join("manifest.json");
    if let Err(e) =
        crate::commands::fac_permissions::write_fac_file_with_mode(&manifest_path, &manifest_data)
    {
        return output_error(
            json_output,
            "fac_bundle_manifest_write_failed",
            &format!("failed to write manifest: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    let result = serde_json::json!({
        "status": "exported",
        "job_id": args.job_id,
        "envelope_path": envelope_path.display().to_string(),
        "manifest_path": manifest_path.display().to_string(),
        "content_hash": envelope.content_hash,
        "blob_count": envelope.blob_refs.len(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );

    exit_codes::SUCCESS
}

/// Open a file for reading without following symlinks (`O_NOFOLLOW` on Unix).
///
/// On non-Unix platforms, falls back to a plain open (no symlink protection).
fn open_no_follow_for_import(path: &std::path::Path) -> Result<std::fs::File, std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }

    #[cfg(not(unix))]
    {
        std::fs::File::open(path)
    }
}

/// Runs `apm2 fac bundle import <path>`.
///
/// Uses single-handle open with `O_NOFOLLOW` + `fstat` + bounded streaming
/// read to avoid TOCTOU between metadata check and read. The same file
/// descriptor is used for size validation and data read.
fn run_bundle_import(args: &BundleImportArgs, json_output: bool) -> u8 {
    use std::io::Read;

    let path = &args.path;
    let bundle_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let envelope_path = bundle_dir.join("envelope.json");

    // Open once with O_NOFOLLOW — refuses symlinks at the kernel level.
    let file = match open_no_follow_for_import(path) {
        Ok(f) => f,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_import_read_failed",
                &format!("cannot open {}: {e}", path.display()),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // fstat on the opened fd — no TOCTOU race.
    let metadata = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_import_read_failed",
                &format!("cannot fstat {}: {e}", path.display()),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Reject non-regular files (symlinks already refused by O_NOFOLLOW;
    // this catches devices, FIFOs, etc.).
    if !metadata.is_file() {
        return output_error(
            json_output,
            "fac_bundle_import_not_regular_file",
            &format!("manifest path is not a regular file: {}", path.display()),
            exit_codes::VALIDATION_ERROR,
        );
    }

    if metadata.len() > MAX_BUNDLE_MANIFEST_FILE_SIZE {
        return output_error(
            json_output,
            "fac_bundle_import_too_large",
            &format!(
                "manifest file too large: {} bytes > {} max",
                metadata.len(),
                MAX_BUNDLE_MANIFEST_FILE_SIZE
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Bounded streaming read from the same handle (no second open).
    let mut data = Vec::new();
    let read_result = file
        .take(MAX_BUNDLE_MANIFEST_FILE_SIZE + 1)
        .read_to_end(&mut data);
    match read_result {
        Ok(_) => {},
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_import_read_failed",
                &format!("cannot read {}: {e}", path.display()),
                exit_codes::GENERIC_ERROR,
            );
        },
    }

    // Belt-and-suspenders: re-check after streaming in case fstat size
    // was stale (filesystem bug) or a non-regular file sneaked past.
    if data.len() as u64 > MAX_BUNDLE_MANIFEST_FILE_SIZE {
        return output_error(
            json_output,
            "fac_bundle_import_too_large",
            &format!(
                "manifest data too large after read: {} bytes > {} max",
                data.len(),
                MAX_BUNDLE_MANIFEST_FILE_SIZE
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Fail-closed manifest validation.
    let manifest = match apm2_core::fac::evidence_bundle::import_evidence_bundle_manifest(&data) {
        Ok(env) => env,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_import_manifest_validation_failed",
                &format!("bundle manifest import rejected (fail-closed): {e}"),
                exit_codes::VALIDATION_ERROR,
            );
        },
    };

    let envelope_file = match open_no_follow_for_import(&envelope_path) {
        Ok(f) => f,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_import_read_failed",
                &format!("cannot open {}: {e}", envelope_path.display()),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let envelope_metadata = match envelope_file.metadata() {
        Ok(m) => m,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_import_read_failed",
                &format!("cannot fstat envelope {}: {e}", envelope_path.display()),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    if !envelope_metadata.is_file() {
        return output_error(
            json_output,
            "fac_bundle_import_not_regular_file",
            &format!(
                "envelope path is not a regular file: {}",
                envelope_path.display()
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    if envelope_metadata.len() > MAX_BUNDLE_ENVELOPE_FILE_SIZE {
        return output_error(
            json_output,
            "fac_bundle_import_too_large",
            &format!(
                "envelope file too large: {} bytes > {} max",
                envelope_metadata.len(),
                MAX_BUNDLE_ENVELOPE_FILE_SIZE
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    let mut envelope_data = Vec::new();
    let envelope_read_result = envelope_file
        .take(MAX_BUNDLE_ENVELOPE_FILE_SIZE + 1)
        .read_to_end(&mut envelope_data);
    match envelope_read_result {
        Ok(_) => {},
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_import_read_failed",
                &format!("cannot read {}: {e}", envelope_path.display()),
                exit_codes::GENERIC_ERROR,
            );
        },
    }

    if envelope_data.len() as u64 > MAX_BUNDLE_ENVELOPE_FILE_SIZE {
        return output_error(
            json_output,
            "fac_bundle_import_too_large",
            &format!(
                "envelope data too large after read: {} bytes > {} max",
                envelope_data.len(),
                MAX_BUNDLE_ENVELOPE_FILE_SIZE
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    let envelope = match apm2_core::fac::evidence_bundle::import_evidence_bundle(&envelope_data) {
        Ok(env) => env,
        Err(e) => {
            return output_error(
                json_output,
                "fac_bundle_import_validation_failed",
                &format!("envelope import rejected (fail-closed): {e}"),
                exit_codes::VALIDATION_ERROR,
            );
        },
    };

    if manifest.envelope_content_hash != envelope.content_hash {
        return output_error(
            json_output,
            "fac_bundle_import_validation_failed",
            &format!(
                "manifest envelope hash mismatch: manifest={}, envelope={}",
                manifest.envelope_content_hash, envelope.content_hash
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    if manifest.blob_count != envelope.blob_refs.len() {
        return output_error(
            json_output,
            "fac_bundle_import_validation_failed",
            &format!(
                "manifest blob_count mismatch: manifest={}, envelope={}",
                manifest.blob_count,
                envelope.blob_refs.len()
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    let has_envelope_entry = manifest.entries.iter().any(|entry| {
        entry.role == "envelope" && entry.content_hash_ref == manifest.envelope_content_hash
    });
    if !has_envelope_entry {
        return output_error(
            json_output,
            "fac_bundle_import_validation_failed",
            "manifest does not contain a matching envelope entry",
            exit_codes::VALIDATION_ERROR,
        );
    }

    if !envelope.blob_refs.is_empty() {
        if let Err(e) = apm2_core::fac::evidence_bundle::verify_blob_refs(&envelope, bundle_dir) {
            return output_error(
                json_output,
                "fac_bundle_import_blob_verification_failed",
                &format!("blob verification failed (fail-closed): {e}"),
                exit_codes::VALIDATION_ERROR,
            );
        }
    }

    let result = serde_json::json!({
        "status": "imported",
        "job_id": envelope.receipt.job_id,
        "schema": envelope.schema,
        "content_hash": envelope.content_hash,
        "boundary_source": format!("{:?}", envelope.boundary_check.source),
        "queue_admission_verdict": envelope.economics_trace.queue_admission.verdict,
        "budget_admission_verdict": envelope.economics_trace.budget_admission.verdict,
        "blob_count": envelope.blob_refs.len(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
    exit_codes::SUCCESS
}

// =============================================================================
// Metrics (TCK-00551)
// =============================================================================

/// Default observation window: 24 hours (in seconds).
const DEFAULT_METRICS_WINDOW_SECS: u64 = 86_400;

/// Coarse pre-filter margin (seconds) for the metrics observation window.
///
/// Headers within +/-1 day of the requested observation window are candidates
/// for receipt verification. This is a **performance optimization only** to
/// avoid verifying every receipt in the store.  The authoritative window check
/// uses the verified receipt's `timestamp_secs` -- this margin is NOT a
/// security boundary.
const COARSE_PREFILTER_MARGIN_SECS: u64 = 86_400;

/// Maximum number of job receipts to load for metrics computation.
///
/// At 64 KiB per receipt (`MAX_JOB_RECEIPT_SIZE`), 16,384 receipts consumes
/// at most ~1 GiB. This hard cap prevents unbounded memory growth when
/// the receipt store contains a very large number of receipts within the
/// observation window (MINOR-2 fix).
const MAX_METRICS_RECEIPTS: usize = 16_384;

/// Execute `apm2 fac metrics`.
fn run_metrics(args: &MetricsArgs, json_output: bool) -> u8 {
    let Some(apm2_home) = apm2_core::github::resolve_apm2_home() else {
        return output_error(
            json_output,
            "apm2_home_not_found",
            "Cannot resolve APM2_HOME for receipt store",
            exit_codes::GENERIC_ERROR,
        );
    };

    let receipts_dir = apm2_home.join("private").join("fac").join("receipts");

    // Resolve observation window.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let since_secs = args
        .since
        .unwrap_or_else(|| now_secs.saturating_sub(DEFAULT_METRICS_WINDOW_SECS));
    let until_secs = args.until.unwrap_or(now_secs);

    // Load all receipt headers from the index, with completeness signal.
    let headers_result = apm2_core::fac::list_receipt_headers(&receipts_dir);
    let index_may_be_incomplete = headers_result.may_be_incomplete;

    // ---------------------------------------------------------------
    // Pass 1: Iterate ALL headers, verify each receipt, then apply the
    // authoritative time-window gate using the VERIFIED receipt's
    // timestamp_secs — NOT the non-authoritative index header timestamp.
    //
    // Security invariant (round 9 fix): The receipt index is attacker-
    // writable (A2 threat model).  An adversary can modify header
    // timestamps to move receipts across the observation window boundary
    // without breaking content-hash verification.  To prevent timestamp
    // poisoning, we:
    //   1. Apply a coarse pre-filter using the header timestamp with a generous
    //      margin (±1 day) as a PERFORMANCE OPTIMIZATION ONLY — this is NOT a
    //      security boundary.
    //   2. Verify the receipt via lookup_receipt_by_hash (BLAKE3 integrity).
    //   3. Gate window inclusion on receipt.timestamp_secs (authoritative).
    //   4. Detect header-vs-receipt timestamp mismatches as tamper evidence.
    //
    // Streaming verification: each receipt is loaded, verified, and
    // counted one at a time.  Only the receipt loaded for detail
    // analysis (pass 2) is retained in memory; the verification-only
    // receipts are dropped immediately after counting.
    // ---------------------------------------------------------------

    let mut header_counts = apm2_core::fac::HeaderCounts::default();
    let mut unverified_headers_skipped: u64 = 0;
    let mut timestamp_mismatches: u64 = 0;
    // Collect verified headers for pass 2 (detail analysis).
    // We store (header_ref_index, verified_receipt) pairs so pass 2
    // can reuse already-loaded receipts without re-reading from disk.
    let mut verified_window: Vec<(usize, apm2_core::fac::FacJobReceiptV1)> = Vec::new();
    let mut truncated = false;

    // Coarse window bounds (with margin) for pre-filter.
    let coarse_since = since_secs.saturating_sub(COARSE_PREFILTER_MARGIN_SECS);
    let coarse_until = until_secs.saturating_add(COARSE_PREFILTER_MARGIN_SECS);

    for (idx, header) in headers_result.headers.iter().enumerate() {
        // Coarse pre-filter using the non-authoritative header timestamp.
        // This is a PERFORMANCE OPTIMIZATION ONLY to avoid verifying every
        // receipt in the store.  The authoritative window check below uses
        // the verified receipt's timestamp_secs.
        if header.timestamp_secs < coarse_since || header.timestamp_secs > coarse_until {
            continue;
        }

        // Verify: content_hash must bind to a verified receipt in the store.
        // lookup_receipt_by_hash validates digest format, loads with bounded
        // I/O + O_NOFOLLOW, and recomputes the BLAKE3-256 hash for integrity.
        let Some(receipt) =
            apm2_core::fac::lookup_receipt_by_hash(&receipts_dir, &header.content_hash)
        else {
            // Verification failed: forged/tampered/missing receipt.
            // Fail-closed: do NOT count this header.
            unverified_headers_skipped += 1;
            continue;
        };

        // Tamper detection: compare the index header's timestamp against the
        // verified receipt's timestamp.  A mismatch means the index was
        // modified to move this receipt across observation window boundaries.
        if header.timestamp_secs != receipt.timestamp_secs {
            timestamp_mismatches += 1;
            // Fail-closed: exclude mismatched receipts from ALL metrics.
            // The receipt's content is valid but the index entry is tampered,
            // so including it would reward the attacker's manipulation.
            continue;
        }

        // Authoritative window gate: use the VERIFIED receipt's timestamp.
        // This is the security boundary — NOT the header timestamp.
        if receipt.timestamp_secs < since_secs || receipt.timestamp_secs > until_secs {
            continue;
        }

        // Verified and within the authoritative window — count using the
        // receipt's actual outcome (not the potentially-forged index header
        // outcome).
        header_counts.total += 1;
        match receipt.outcome {
            apm2_core::fac::FacJobOutcome::Completed => header_counts.completed += 1,
            apm2_core::fac::FacJobOutcome::Denied => header_counts.denied += 1,
            apm2_core::fac::FacJobOutcome::Quarantined => {
                header_counts.quarantined += 1;
            },
            apm2_core::fac::FacJobOutcome::Cancelled
            | apm2_core::fac::FacJobOutcome::CancellationRequested => {
                header_counts.cancelled += 1;
            },
            // Fail-closed: unknown outcome variants are counted in total
            // but not attributed to any category.
            _ => {},
        }

        // Retain for pass 2 if within the detail cap.
        if verified_window.len() < MAX_METRICS_RECEIPTS {
            verified_window.push((idx, receipt));
        } else {
            truncated = true;
            // Drop the receipt — only needed for counting, which is
            // done.
        }
    }

    // ---------------------------------------------------------------
    // Pass 2: Extract already-loaded verified receipts for detail
    // analysis (latency percentiles, denial-reason breakdowns).
    // These were retained during pass 1, bounded by MAX_METRICS_RECEIPTS.
    // ---------------------------------------------------------------
    let job_receipts: Vec<apm2_core::fac::FacJobReceiptV1> =
        verified_window.into_iter().map(|(_idx, r)| r).collect();

    if truncated {
        eprintln!(
            "warning: verified receipt count exceeds MAX_METRICS_RECEIPTS \
             ({MAX_METRICS_RECEIPTS}); latency and denial-reason details are \
             computed from the first {MAX_METRICS_RECEIPTS} receipts only \
             (aggregate counts cover all verified receipts)"
        );
    }

    if unverified_headers_skipped > 0 {
        eprintln!(
            "warning: {unverified_headers_skipped} receipt index header(s) failed \
             content-hash verification and were excluded from aggregate counts. \
             This may indicate index corruption or tampered receipt files."
        );
    }

    if timestamp_mismatches > 0 {
        eprintln!(
            "warning: {timestamp_mismatches} receipt index header(s) had a \
             timestamp_secs mismatch versus the verified receipt payload. \
             These receipts were excluded from metrics. This is a strong tamper \
             indicator: the receipt index may have been modified to shift \
             receipts across observation window boundaries."
        );
    }

    if index_may_be_incomplete {
        eprintln!(
            "warning: receipt index is at capacity and may not contain all \
             receipts in the store. Aggregate counts may undercount. \
             Run `apm2 fac reindex` to rebuild."
        );
    }

    // Load GC receipts.
    let gc_result = apm2_core::fac::load_gc_receipts(&receipts_dir, since_secs);
    let gc_receipts_truncated = gc_result.truncated;
    // Filter GC receipts by until bound.
    let gc_receipts: Vec<_> = gc_result
        .receipts
        .into_iter()
        .filter(|r| r.timestamp_secs <= until_secs)
        .collect();

    let input = apm2_core::fac::MetricsInput {
        job_receipts: &job_receipts,
        gc_receipts: &gc_receipts,
        since_epoch_secs: since_secs,
        until_epoch_secs: until_secs,
        header_counts: Some(header_counts),
    };

    let mut summary = apm2_core::fac::compute_metrics(&input);
    summary.gc_receipts_truncated = gc_receipts_truncated;
    summary.job_receipts_truncated = truncated;
    summary.aggregates_may_be_incomplete = index_may_be_incomplete;
    summary.unverified_headers_skipped = unverified_headers_skipped;
    summary.timestamp_mismatches = timestamp_mismatches;

    // TCK-00606 S12: FAC commands are machine-output only.
    match serde_json::to_string_pretty(&summary) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            return output_error(
                true,
                "serialization_error",
                &format!("Failed to serialize metrics: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    }

    exit_codes::SUCCESS
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use apm2_core::fac::LANE_CORRUPT_MARKER_SCHEMA;
    use clap::Parser;

    use super::*;

    #[derive(Parser, Debug)]
    struct FacLogsCliHarness {
        #[arg(long, default_value_t = false)]
        json: bool,

        #[command(subcommand)]
        subcommand: FacSubcommand,
    }

    fn assert_fac_command_parses(args: &[&str]) {
        FacLogsCliHarness::try_parse_from(args.iter().copied())
            .unwrap_or_else(|err| panic!("failed to parse `{}`: {err}", args.join(" ")));
    }

    // KNOWN ISSUE (f-685-security-1771186259820160-0): Apm2HomeGuard mutates
    // process-wide environment variables via std::env::set_var, which is inherently
    // racy under parallel test execution. This is a pre-existing pattern used
    // across the test suite (apm2-cli, apm2-daemon). A proper fix requires
    // either:   (a) adding `serial_test` as a workspace dependency and
    // annotating all       env-mutating tests with `#[serial]`, or
    //   (b) refactoring production code to accept `fac_root` explicitly instead of
    //       reading APM2_HOME from the environment.
    // Both approaches are cross-cutting changes beyond this ticket's scope.
    // Current mitigation: each test uses a unique tempdir, and Apm2HomeGuard
    // restores the previous value on Drop, limiting the blast radius.
    struct Apm2HomeGuard {
        previous: Option<std::ffi::OsString>,
        _env_lock: std::sync::MutexGuard<'static, ()>,
    }

    #[allow(unsafe_code)] // Env var mutation is required for test setup and teardown.
    fn set_apm2_home(home: &std::path::Path) {
        // SAFETY: tests intentionally mutate process-wide environment state and
        // restore it in Drop, matching the project's existing environment
        // test harness pattern. This is inherently racy in parallel test
        // execution — see KNOWN ISSUE above.
        unsafe {
            std::env::set_var("APM2_HOME", home);
        }
    }

    #[allow(unsafe_code)] // Env var restoration is required for test cleanup.
    fn restore_apm2_home(previous: Option<&std::ffi::OsString>) {
        // SAFETY: tests intentionally mutate process-wide environment state and
        // restore it in Drop, matching the project's existing environment
        // test harness pattern.
        unsafe {
            match previous {
                Some(previous) => std::env::set_var("APM2_HOME", previous),
                None => std::env::remove_var("APM2_HOME"),
            }
        }
    }

    impl Apm2HomeGuard {
        fn new(home: &std::path::Path) -> Self {
            let env_lock = crate::commands::env_var_test_lock()
                .lock()
                .expect("serialize env-mutating test");
            let previous = std::env::var_os("APM2_HOME");
            set_apm2_home(home);
            Self {
                previous,
                _env_lock: env_lock,
            }
        }
    }

    impl Drop for Apm2HomeGuard {
        fn drop(&mut self) {
            restore_apm2_home(self.previous.as_ref());
        }
    }

    #[test]
    fn test_doctor_lane_reset_clears_corrupt_marker() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";
        let marker = LaneCorruptMarkerV1 {
            schema: apm2_core::fac::LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            reason: "reset regression".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "2026-02-15T00:00:00Z".to_string(),
        };
        marker.persist(manager.fac_root()).expect("persist marker");
        let status = manager.lane_status(lane_id).expect("initial lane status");
        assert_eq!(status.state, LaneState::Corrupt);

        let reset = doctor_reset_lane_once(&manager, lane_id);
        assert!(reset.is_ok(), "doctor reset should succeed: {reset:?}");
        assert!(
            LaneCorruptMarkerV1::load(manager.fac_root(), lane_id)
                .expect("load marker")
                .is_none()
        );

        let status_after = manager
            .lane_status(lane_id)
            .expect("lane status after reset");
        assert_ne!(status_after.state, LaneState::Corrupt);
    }

    #[test]
    fn test_doctor_lane_reset_removes_all_per_lane_env_dirs() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);

        let mut reset_targets = vec![
            lane_dir.join("workspace"),
            lane_dir.join("target"),
            lane_dir.join("logs"),
        ];
        for &subdir in LANE_ENV_DIRS {
            reset_targets.push(lane_dir.join(subdir));
        }

        for target in &reset_targets {
            std::fs::create_dir_all(target).expect("create lane reset target");
            std::fs::write(target.join("stale-state"), b"stale").expect("write stale state");
        }

        let reset = doctor_reset_lane_once(&manager, lane_id);
        assert!(reset.is_ok(), "doctor reset should succeed: {reset:?}");

        for target in &reset_targets {
            assert!(
                target.exists(),
                "target {} should be recreated by doctor lane reset",
                target.display()
            );
            assert!(
                !target.join("stale-state").exists(),
                "stale-state in {} should be deleted by doctor lane reset",
                target.display()
            );
        }
    }

    #[test]
    fn test_detect_lane_tmp_corruption_flags_transient_residue() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";
        let residue = manager.lane_dir(lane_id).join("tmp").join(".tmp-stale");
        std::fs::write(&residue, b"stale residue").expect("write residue");

        let detection =
            detect_lane_tmp_corruption(&manager, lane_id).expect("tmp corruption detection");
        let detail = detection.expect("residue should be detected");
        assert!(detail.contains("transient residue"));
        assert!(detail.contains(".tmp-stale"));
    }

    #[test]
    fn test_scrub_lane_tmp_dir_removes_nested_entries() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";
        let tmp_dir = manager.lane_dir(lane_id).join("tmp");

        std::fs::write(tmp_dir.join(".tmp-residue"), b"stale").expect("write residue file");
        std::fs::write(tmp_dir.join("leftover.txt"), b"leftover").expect("write leftover file");
        let nested_dir = tmp_dir.join("nested");
        std::fs::create_dir_all(&nested_dir).expect("create nested tmp dir");
        std::fs::write(nested_dir.join("nested.log"), b"nested").expect("write nested file");

        let scrub = scrub_lane_tmp_dir(&manager, lane_id).expect("tmp scrub should succeed");
        assert!(
            scrub.entries_deleted >= 3,
            "expected scrub to delete multiple entries, got {}",
            scrub.entries_deleted
        );
        let remaining = std::fs::read_dir(&tmp_dir)
            .expect("read tmp dir after scrub")
            .count();
        assert_eq!(remaining, 0, "tmp dir should be empty after scrub");
    }

    #[test]
    fn test_scrub_lane_tmp_dir_recreates_tmp_when_path_is_file() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";
        let tmp_dir = manager.lane_dir(lane_id).join("tmp");
        std::fs::remove_dir(&tmp_dir).expect("remove tmp dir");
        std::fs::write(&tmp_dir, b"not-a-dir").expect("write tmp file");

        let scrub = scrub_lane_tmp_dir(&manager, lane_id).expect("tmp scrub should succeed");
        assert_eq!(scrub.entries_deleted, 1);
        assert!(
            tmp_dir.is_dir(),
            "tmp path should be recreated as directory after scrub"
        );
    }

    #[test]
    fn test_scrub_lane_tmp_dir_with_entry_limit_fails_closed() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";
        let nested_dir = manager.lane_dir(lane_id).join("tmp").join("nested");
        std::fs::create_dir_all(&nested_dir).expect("create nested tmp dir");
        for idx in 0..4 {
            std::fs::write(nested_dir.join(format!("file-{idx}.tmp")), b"tmp")
                .expect("write nested tmp file");
        }

        let err = scrub_lane_tmp_dir_with_entry_limit(&manager, lane_id, 2)
            .expect_err("tmp scrub should fail when entry limit is exceeded");
        assert!(
            err.contains("entry bound"),
            "expected entry bound failure, got: {err}"
        );
    }

    #[test]
    fn test_gc_stale_lane_logs_reports_over_quota_lane_log_targets() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";
        let logs_dir = manager.lane_dir(lane_id).join("logs");
        let mut created_job_dirs = Vec::new();
        for idx in 0..6 {
            let job_dir = logs_dir.join(format!("job-{idx:02}"));
            std::fs::create_dir_all(&job_dir).expect("create job log directory");
            let file = std::fs::File::create(job_dir.join("build.log")).expect("create build.log");
            // Sparse file: 20 MiB logical size without heavy write I/O.
            file.set_len(20 * 1024 * 1024)
                .expect("set sparse file size");
            created_job_dirs.push(job_dir);
        }
        let _oldest_dir = created_job_dirs
            .into_iter()
            .min()
            .expect("at least one created job log dir");

        let summary =
            gc_stale_lane_logs(manager.fac_root(), &manager).expect("lane log gc should succeed");
        assert!(
            summary.targets >= 1,
            "expected at least one lane log gc target, got {}",
            summary.targets
        );
        assert_eq!(
            summary.actions_applied + summary.errors,
            summary.targets,
            "every target must resolve to exactly one action or error"
        );
        assert!(
            summary.actions_applied > 0 || summary.errors > 0,
            "gc should report at least one applied action or error for non-empty target set"
        );
    }

    #[test]
    fn test_system_doctor_fix_action_kind_serializes_as_snake_case() {
        let payload = serde_json::to_value(SystemDoctorFixAction {
            action: SystemDoctorFixActionKind::LaneTmpCorruptionDetected,
            status: SystemDoctorFixActionStatus::Blocked,
            lane_id: Some("lane-00".to_string()),
            detail: "tmp residue detected".to_string(),
        })
        .expect("serialize doctor action");
        assert_eq!(
            payload.get("action").and_then(|value| value.as_str()),
            Some("lane_tmp_corruption_detected")
        );
    }

    #[test]
    fn test_lane_reset_liveness_guard_blocks_active_for_non_orphaned_reset() {
        let err =
            enforce_lane_reset_liveness_guard("lane-00", Some("job-123"), |_lane_id, _job_id| {
                FacUnitLiveness::Active {
                    active_units: vec!["apm2-fac-job-lane-00-job-123.service".to_string()],
                }
            })
            .expect_err("active liveness must block reset");
        assert!(
            err.contains("reset blocked while liveness=active"),
            "expected active liveness block detail, got: {err}"
        );
    }

    #[test]
    fn test_lane_reset_liveness_guard_blocks_when_job_id_missing() {
        let err = enforce_lane_reset_liveness_guard("lane-00", None, |_lane_id, _job_id| {
            FacUnitLiveness::Inactive
        })
        .expect_err("missing job_id must block reset");
        assert!(
            err.contains("cannot verify unit liveness without lease job_id"),
            "expected missing job_id guard detail, got: {err}"
        );
    }

    #[test]
    fn test_lane_reset_liveness_guard_allows_inactive() {
        let result =
            enforce_lane_reset_liveness_guard("lane-00", Some("job-123"), |_lane_id, _job_id| {
                FacUnitLiveness::Inactive
            });
        assert!(result.is_ok(), "inactive liveness should allow reset");
    }

    #[test]
    fn test_system_doctor_fix_exit_code_returns_error_for_blocked_actions() {
        let exit_code = system_doctor_fix_exit_code(false, true, false);
        assert_eq!(exit_code, exit_codes::GENERIC_ERROR);
    }

    #[test]
    fn test_system_doctor_fix_exit_code_returns_success_when_clean() {
        let exit_code = system_doctor_fix_exit_code(false, false, false);
        assert_eq!(exit_code, exit_codes::SUCCESS);
    }

    #[test]
    fn test_work_status_response_serialization() {
        let response = WorkStatusResponse {
            work_id: "work-123".to_string(),
            status: "CLAIMED".to_string(),
            actor_id: Some("actor-1".to_string()),
            role: Some("implementer".to_string()),
            latest_episode_id: None,
            latest_receipt_hash: None,
            event_count: 5,
            latest_seq_id: Some(42),
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: WorkStatusResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.work_id, "work-123");
        assert_eq!(restored.status, "CLAIMED");
    }

    #[test]
    fn test_episode_inspect_response_serialization() {
        let response = EpisodeInspectResponse {
            episode_id: "ep-001".to_string(),
            status: "RUNNING".to_string(),
            work_id: Some("work-123".to_string()),
            actor_id: None,
            role: Some("implementer".to_string()),
            tool_log_summary: Some(ToolLogSummary {
                total_executions: 10,
                successful_executions: 8,
                failed_executions: 2,
                total_tokens: 5000,
                total_bytes_io: 100_000,
                total_wall_ms: 30_000,
            }),
            tool_log_index: None,
            event_count: 15,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("ep-001"));
        assert!(json.contains("total_executions"));
    }

    #[test]
    fn test_receipt_show_response_serialization() {
        let response = ReceiptShowResponse {
            hash: "abc123".to_string(),
            receipt_type: "gate_receipt".to_string(),
            size_bytes: 1024,
            content: serde_json::json!({"verdict": "PASS"}),
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: ReceiptShowResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.receipt_type, "gate_receipt");
    }

    #[test]
    fn test_context_rebuild_response_serialization() {
        let response = ContextRebuildResponse {
            role: "implementer".to_string(),
            episode_id: "ep-001".to_string(),
            output_dir: "/tmp/rebuild".to_string(),
            context_pack_hash: "deadbeef".to_string(),
            artifacts_retrieved: 5,
            deterministic: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("deterministic"));
    }

    #[test]
    fn test_detect_receipt_type_gate() {
        let json = serde_json::json!({
            "schema": "apm2.gate_receipt.v1",
            "verdict": "PASS"
        });
        assert_eq!(detect_receipt_type(&json), "gate_receipt");
    }

    #[test]
    fn test_detect_receipt_type_review() {
        let json = serde_json::json!({
            "schema": REVIEW_ARTIFACT_SCHEMA_IDENTIFIER,
            "review_verdict": "APPROVED"
        });
        assert_eq!(detect_receipt_type(&json), "review_receipt");
    }

    #[test]
    fn test_detect_receipt_type_tool_log() {
        let json = serde_json::json!({
            "schema": TOOL_LOG_INDEX_V1_SCHEMA,
            "episode_id": "ep-001"
        });
        assert_eq!(detect_receipt_type(&json), "tool_log_index");
    }

    #[test]
    fn test_detect_receipt_type_unknown() {
        let json = serde_json::json!({
            "some_field": "value"
        });
        assert_eq!(detect_receipt_type(&json), "unknown");
    }

    /// SECURITY TEST: Verify responses reject unknown fields.
    #[test]
    fn test_work_status_response_rejects_unknown_fields() {
        let json = r#"{
            "work_id": "work-1",
            "status": "CLAIMED",
            "event_count": 1,
            "malicious": "value"
        }"#;

        let result: Result<WorkStatusResponse, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "WorkStatusResponse should reject unknown fields"
        );
    }

    #[test]
    fn test_resolve_ledger_path_explicit() {
        let explicit = PathBuf::from("/explicit/path/ledger.db");
        let resolved = resolve_ledger_path(Some(&explicit));
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn test_resolve_cas_path_explicit() {
        let explicit = PathBuf::from("/explicit/path/cas");
        let resolved = resolve_cas_path(Some(&explicit));
        assert_eq!(resolved, explicit);
    }

    // --- Core Logic Tests (Added per Review) ---

    #[test]
    fn test_extract_work_info_success() {
        let payload = serde_json::json!({
            "work_id": "work-123",
            "actor_id": "actor-1",
            "role": "implementer"
        });
        let event = EventRecord::new(
            "work_claimed",
            "session-1",
            "actor-1",
            serde_json::to_vec(&payload).unwrap(),
        );

        let info = extract_work_info(&event, "work-123").expect("should extract");
        assert!(
            info.episode_id.is_none(),
            "work_claimed payload has no episode_id"
        );
    }

    #[test]
    fn test_extract_work_info_metadata_first_for_legacy_rows() {
        let payload = serde_json::json!({
            "role": "implementer"
        });
        let event = EventRecord::new(
            "work_claimed",
            "work-123", // legacy compat maps work_id -> session_id
            "actor-from-row",
            serde_json::to_vec(&payload).unwrap(),
        );

        let info = extract_work_info(&event, "work-123").expect("should match via metadata");
        assert!(
            info.episode_id.is_none(),
            "legacy work rows should not infer episode_id"
        );
    }

    #[test]
    fn test_extract_work_info_payload_fallback_for_episode_rows() {
        let payload = serde_json::json!({
            "work_id": "work-123"
        });
        let event = EventRecord::new(
            "episode_spawned",
            "episode-001", // daemon stores episode_id in legacy work_id column
            "daemon",
            serde_json::to_vec(&payload).unwrap(),
        );

        let info =
            extract_work_info(&event, "work-123").expect("should match via payload fallback");
        assert_eq!(info.episode_id.as_deref(), Some("episode-001"));
    }

    #[test]
    fn test_extract_work_info_mismatch() {
        let payload = serde_json::json!({
            "work_id": "work-456",
            "actor_id": "actor-1"
        });
        let event = EventRecord::new(
            "work_claimed",
            "session-1",
            "actor-1",
            serde_json::to_vec(&payload).unwrap(),
        );

        assert!(extract_work_info(&event, "work-123").is_none());
    }

    #[test]
    fn test_extract_work_info_invalid_json() {
        let event = EventRecord::new("work_claimed", "session-1", "actor-1", b"not-json".to_vec());

        assert!(extract_work_info(&event, "work-123").is_none());
    }

    #[test]
    fn test_extract_episode_info_via_session_id() {
        let payload = serde_json::json!({
            "work_id": "work-123",
            "role": "implementer"
        });
        let event = EventRecord::new(
            "tool_executed",
            "ep-001", // session_id matches episode_id
            "actor-1",
            serde_json::to_vec(&payload).unwrap(),
        );

        let info = extract_episode_info(&event, "ep-001").expect("should extract via session_id");
        assert_eq!(info.work_id.as_deref(), Some("work-123"));
    }

    #[test]
    fn test_extract_episode_info_via_payload_field() {
        let payload = serde_json::json!({
            "episode_id": "ep-001",
            "work_id": "work-123"
        });
        let event = EventRecord::new(
            "episode_spawned",
            "session-X", // session_id does NOT match
            "actor-1",
            serde_json::to_vec(&payload).unwrap(),
        );

        let info = extract_episode_info(&event, "ep-001").expect("should extract via payload");
        assert_eq!(info.work_id.as_deref(), Some("work-123"));
    }

    #[test]
    fn test_calculate_start_cursor() {
        // Mocking ledger state is hard without an in-memory ledger,
        // so we test the logic math here conceptually:
        let max_seq = 15_000u64;
        let limit = 10_000u64;
        let start = max_seq.saturating_sub(limit).max(1);
        assert_eq!(start, 5_000);

        let max_seq_small = 500u64;
        let start_small = max_seq_small.saturating_sub(limit).max(1);
        assert_eq!(start_small, 1);
    }

    // --- SECURITY: Constant-time hash comparison tests ---

    #[test]
    fn test_constant_time_hash_eq_identical() {
        let hash1 = [0x42u8; 32];
        let hash2 = [0x42u8; 32];
        assert!(constant_time_hash_eq(&hash1, &hash2));
    }

    #[test]
    fn test_constant_time_hash_eq_different() {
        let hash1 = [0x42u8; 32];
        let mut hash2 = [0x42u8; 32];
        hash2[31] = 0x00; // Single byte difference
        assert!(!constant_time_hash_eq(&hash1, &hash2));
    }

    #[test]
    fn test_constant_time_hash_eq_length_mismatch() {
        let hash1 = [0x42u8; 32];
        let hash2 = [0x42u8; 16]; // Different length
        assert!(!constant_time_hash_eq(&hash1, &hash2));
    }

    #[test]
    fn test_constant_time_hash_eq_empty() {
        let hash1: [u8; 0] = [];
        let hash2: [u8; 0] = [];
        assert!(constant_time_hash_eq(&hash1, &hash2));
    }

    #[test]
    fn test_parse_cas_hash_32_accepts_valid_hash() {
        let hash_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let parsed = parse_cas_hash_32("artifact_hash", hash_hex).expect("valid hash should parse");
        assert_eq!(parsed.len(), 32);
        assert_eq!(parsed[0], 0x01);
        assert_eq!(parsed[31], 0xef);
    }

    #[test]
    fn test_parse_cas_hash_32_rejects_short_hash() {
        let hash_hex = "deadbeef";
        let error =
            parse_cas_hash_32("artifact_hash", hash_hex).expect_err("short hash should fail");
        assert!(matches!(error, CasHashParseError::InvalidLength { .. }));
    }

    #[test]
    fn test_parse_cas_hash_32_rejects_non_hex() {
        let error = parse_cas_hash_32(
            "artifact_hash",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        )
        .expect_err("non-hex hash should fail");
        assert!(matches!(error, CasHashParseError::InvalidHex { .. }));
    }

    #[test]
    fn test_parse_cas_hash_to_path_roundtrip() {
        let cas_path = std::path::Path::new("/tmp/cas");
        let hash_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let (path, bytes) = parse_cas_hash_to_path(cas_path, hash_hex, "artifact_hash")
            .expect("parse should succeed");
        assert_eq!(bytes[0], 0xff);
        assert_eq!(
            path,
            cas_path.join("objects").join("ffff").join(&hash_hex[4..])
        );
    }

    // --- detect_receipt_type prefix matching tests ---

    #[test]
    fn test_detect_receipt_type_prefix_matching_prevents_false_positive() {
        // Should NOT match because "my_gate_receipt" doesn't start with
        // "apm2.gate_receipt."
        let json = serde_json::json!({
            "schema": "my_gate_receipt.v1"
        });
        // Falls through to returning the schema itself, not "gate_receipt"
        assert_eq!(detect_receipt_type(&json), "my_gate_receipt.v1");
    }

    #[test]
    fn test_detect_receipt_type_exact_prefix_merge() {
        let json = serde_json::json!({
            "schema": "apm2.merge_receipt.v2"
        });
        assert_eq!(detect_receipt_type(&json), "merge_receipt");
    }

    #[test]
    fn test_detect_receipt_type_exact_prefix_projection() {
        let json = serde_json::json!({
            "schema": "apm2.projection.v1"
        });
        assert_eq!(detect_receipt_type(&json), "projection_receipt");
    }

    #[test]
    fn test_logs_subcommand_json_flag_parses() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "logs", "--pr", "615", "--json"])
            .expect("logs parser should accept subcommand json flag");

        assert!(!parsed.json);
        match parsed.subcommand {
            FacSubcommand::Logs(args) => {
                assert_eq!(args.pr, Some(615));
                assert!(args.json);
            },
            other => panic!("expected logs subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_logs_global_json_flag_parses() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "--json", "logs", "--pr", "615"])
            .expect("logs parser should accept global json flag");

        assert!(parsed.json);
        match parsed.subcommand {
            FacSubcommand::Logs(args) => {
                assert_eq!(args.pr, Some(615));
                assert!(!args.json);
            },
            other => panic!("expected logs subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_gates_timeout_default_is_600_seconds() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "gates"])
            .expect("gates parser should apply defaults");
        match parsed.subcommand {
            FacSubcommand::Gates(args) => {
                assert_eq!(args.timeout_seconds, 600);
                assert_eq!(
                    args.gate_profile,
                    fac_review::GateThroughputProfile::Throughput
                );
                assert_eq!(args.cpu_quota, "auto");
                assert!(args.wait);
                assert!(!args.no_wait);
                assert_eq!(args.wait_timeout_secs, 1200);
            },
            other => panic!("expected gates subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_gates_wait_flags_parse() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "gates",
            "--wait",
            "--wait-timeout-secs",
            "90",
        ])
        .expect("gates parser should accept wait flags");
        match parsed.subcommand {
            FacSubcommand::Gates(args) => {
                assert!(args.wait);
                assert!(!args.no_wait);
                assert_eq!(args.wait_timeout_secs, 90);
            },
            other => panic!("expected gates subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_gates_no_wait_flag_parse() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "gates", "--no-wait"])
            .expect("gates parser should accept --no-wait");
        match parsed.subcommand {
            FacSubcommand::Gates(args) => {
                assert!(args.wait);
                assert!(args.no_wait);
            },
            other => panic!("expected gates subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_preflight_credential_runtime_flags_parse() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "preflight",
            "credential",
            "runtime",
            "--json",
        ])
        .expect("preflight credential runtime should parse");
        match parsed.subcommand {
            FacSubcommand::Preflight(args) => match args.subcommand {
                PreflightSubcommand::Credential(credential_args) => {
                    assert_eq!(credential_args.mode, fac_preflight::CredentialMode::Runtime);
                    assert!(credential_args.paths.is_empty());
                    assert!(credential_args.json);
                },
                other @ PreflightSubcommand::Authorization(_) => {
                    panic!("expected preflight credential subcommand, got {other:?}")
                },
            },
            other => panic!("expected preflight subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_preflight_credential_lint_paths_parse() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "preflight",
            "credential",
            "lint",
            ".github/workflows/ci.yml",
            "crates/apm2-cli/src/commands/fac_preflight.rs",
        ])
        .expect("preflight credential lint should parse");
        match parsed.subcommand {
            FacSubcommand::Preflight(args) => match args.subcommand {
                PreflightSubcommand::Credential(credential_args) => {
                    assert_eq!(credential_args.mode, fac_preflight::CredentialMode::Lint);
                    assert_eq!(credential_args.paths.len(), 2);
                    assert_eq!(
                        credential_args.paths[0],
                        PathBuf::from(".github/workflows/ci.yml")
                    );
                    assert_eq!(
                        credential_args.paths[1],
                        PathBuf::from("crates/apm2-cli/src/commands/fac_preflight.rs")
                    );
                    assert!(!credential_args.json);
                },
                other @ PreflightSubcommand::Authorization(_) => {
                    panic!("expected preflight credential subcommand, got {other:?}")
                },
            },
            other => panic!("expected preflight subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_preflight_authorization_flags_parse() {
        let parsed =
            FacLogsCliHarness::try_parse_from(["fac", "preflight", "authorization", "--json"])
                .expect("preflight authorization should parse");
        match parsed.subcommand {
            FacSubcommand::Preflight(args) => match args.subcommand {
                PreflightSubcommand::Authorization(auth_args) => {
                    assert!(auth_args.json);
                },
                other @ PreflightSubcommand::Credential(_) => {
                    panic!("expected preflight authorization subcommand, got {other:?}")
                },
            },
            other => panic!("expected preflight subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_subcommand_machine_output_detection_for_nested_json() {
        let review_findings = FacSubcommand::Review(ReviewArgs {
            subcommand: ReviewSubcommand::Findings(ReviewFindingsArgs {
                pr: Some(615),
                sha: None,
                refresh: false,
                json: true,
            }),
        });
        assert!(subcommand_requests_machine_output(&review_findings));

        let recover = FacSubcommand::Recover(RecoverArgs {
            pr: Some(615),
            force: false,
            refresh_identity: false,
            reap_stale_agents: false,
            reset_lifecycle: false,
            all: false,
            json: true,
        });
        assert!(subcommand_requests_machine_output(&recover));

        let restart = FacSubcommand::Restart(RestartArgs {
            pr: Some(615),
            force: false,
            refresh_identity: false,
            json: false,
        });
        assert!(subcommand_requests_machine_output(&restart));

        let worker = FacSubcommand::Worker(WorkerArgs {
            once: true,
            poll_interval_secs: 1,
            max_jobs: 1,
            print_unit: false,
            json: false,
        });
        assert!(subcommand_requests_machine_output(&worker));

        let preflight = FacSubcommand::Preflight(PreflightArgs {
            subcommand: PreflightSubcommand::Authorization(PreflightAuthorizationArgs {
                json: true,
            }),
        });
        assert!(subcommand_requests_machine_output(&preflight));
    }

    #[test]
    fn test_doctor_fix_flag_parses() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "doctor", "--pr", "615", "--fix"])
            .expect("doctor --fix should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert_eq!(args.pr, Some(615));
                assert_eq!(args.repo, None);
                assert!(args.fix);
                assert!(!args.full);
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_fix_without_pr_parses_for_system_reconcile() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "doctor", "--fix"])
            .expect("doctor --fix without --pr should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert!(args.fix);
                assert!(args.pr.is_none());
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_should_attempt_cleanup_scrub_matches_entry_limit_reason() {
        assert!(should_attempt_cleanup_scrub(
            "directory /tmp/lane/tmp has more than 10000 entries"
        ));
        assert!(!should_attempt_cleanup_scrub("operator-marked corrupt"));
    }

    #[test]
    fn test_refused_delete_mentions_tmp_matches_tmp_root() {
        let receipts = vec![RefusedDeleteReceipt {
            root: PathBuf::from("/tmp/apm2/private/fac/lanes/lane-00/tmp"),
            allowed_parent: PathBuf::from("/tmp/apm2/private/fac/lanes"),
            reason: "directory has more than 10000 entries".to_string(),
            mark_corrupt: true,
        }];
        assert!(refused_delete_mentions_tmp(&receipts));
    }

    #[test]
    fn test_doctor_full_flag_parses() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "doctor", "--full"])
            .expect("doctor --full should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert!(args.full);
                assert!(!args.tracked_prs);
                assert!(args.pr.is_none());
                assert!(args.repo.is_none());
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_tracked_prs_flag_parses() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "doctor", "--tracked-prs"])
            .expect("doctor --tracked-prs should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert!(args.tracked_prs);
                assert!(!args.full);
                assert!(args.pr.is_none());
                assert!(args.repo.is_none());
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_machine_spec_flag_parses() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "doctor", "--machine-spec"])
            .expect("doctor --machine-spec should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert!(args.machine_spec);
                assert!(args.pr.is_none());
                assert!(args.repo.is_none());
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_wait_flags_parse() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--wait-for-recommended-action",
            "--poll-interval-seconds",
            "2",
            "--wait-timeout-seconds",
            "30",
            "--exit-on",
            "fix,merge",
        ])
        .expect("doctor wait flags should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert_eq!(args.pr, Some(615));
                assert!(args.wait_for_recommended_action);
                assert_eq!(args.poll_interval_seconds, 2);
                assert_eq!(args.wait_timeout_seconds, 30);
                assert_eq!(
                    args.exit_on,
                    vec![DoctorExitActionArg::Fix, DoctorExitActionArg::Merge]
                );
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_wait_alias_parses() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "doctor", "--pr", "615", "--wait"])
            .expect("doctor --wait alias should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert_eq!(args.pr, Some(615));
                assert!(args.wait_for_recommended_action);
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_wait_timeout_secs_alias_parses() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--wait-for-recommended-action",
            "--wait-timeout-secs",
            "30",
        ])
        .expect("doctor --wait-timeout-secs alias should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert_eq!(args.wait_timeout_seconds, 30);
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_repo_filter_parses() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--repo",
            "guardian-intelligence/apm2",
        ])
        .expect("doctor --repo should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert!(args.pr.is_none());
                assert_eq!(args.repo.as_deref(), Some("guardian-intelligence/apm2"));
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_repo_filter_rejects_invalid_value() {
        let err = FacLogsCliHarness::try_parse_from(["fac", "doctor", "--repo", "invalid_repo"])
            .expect_err("invalid --repo should fail parsing");
        let rendered = err.to_string();
        assert!(rendered.contains("invalid repository format"));
        assert!(rendered.contains("owner/repo"));
    }

    #[test]
    fn test_doctor_repo_filter_conflicts_with_pr() {
        let err = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--repo",
            "guardian-intelligence/apm2",
        ])
        .expect_err("--repo and --pr should conflict");
        let rendered = err.to_string();
        assert!(rendered.contains("cannot be used with"));
        assert!(rendered.contains("--pr"));
    }

    #[test]
    fn test_doctor_wait_timeout_defaults_to_1200_seconds() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--wait-for-recommended-action",
        ])
        .expect("doctor wait default timeout should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert_eq!(args.wait_timeout_seconds, 1200);
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_wait_timeout_accepts_maximum_1200_seconds() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--wait-for-recommended-action",
            "--wait-timeout-seconds",
            "1200",
        ])
        .expect("1200s timeout should be accepted");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert_eq!(args.wait_timeout_seconds, 1200);
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_wait_timeout_rejects_values_over_1200_seconds() {
        let err = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--wait-for-recommended-action",
            "--wait-timeout-seconds",
            "1201",
        ])
        .expect_err("timeout above cap should fail");
        let rendered = err.to_string();
        assert!(rendered.contains("between 5 and 1200 seconds"));
        assert!(rendered.contains("diagnose the problem"));
    }

    #[test]
    fn test_doctor_wait_exit_on_rejects_unknown_action() {
        let err = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--wait-for-recommended-action",
            "--exit-on",
            "wait",
        ])
        .expect_err("unknown --exit-on action should fail parsing");
        let rendered = err.to_string();
        assert!(rendered.contains("wait"));
    }

    #[test]
    fn test_doctor_wait_exit_on_accepts_escalate_action() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--wait-for-recommended-action",
            "--exit-on",
            "escalate",
        ])
        .expect("escalate should parse as a valid doctor exit action");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert_eq!(args.exit_on, vec![DoctorExitActionArg::Escalate]);
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_wait_exit_on_accepts_done_action() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--wait-for-recommended-action",
            "--exit-on",
            "done",
        ])
        .expect("done should parse as a valid doctor exit action");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert_eq!(args.exit_on, vec![DoctorExitActionArg::Done]);
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_wait_exit_on_accepts_approve_action() {
        let parsed = FacLogsCliHarness::try_parse_from([
            "fac",
            "doctor",
            "--pr",
            "615",
            "--wait-for-recommended-action",
            "--exit-on",
            "approve",
        ])
        .expect("approve should parse as a valid doctor exit action");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert_eq!(args.exit_on, vec![DoctorExitActionArg::Approve]);
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_exit_action_enum_matches_fac_review_supported_actions() {
        let mut enum_actions = vec![
            DoctorExitActionArg::Fix.as_str(),
            DoctorExitActionArg::Escalate.as_str(),
            DoctorExitActionArg::Merge.as_str(),
            DoctorExitActionArg::Done.as_str(),
            DoctorExitActionArg::Approve.as_str(),
            DoctorExitActionArg::DispatchImplementor.as_str(),
            DoctorExitActionArg::RestartReviews.as_str(),
        ];
        enum_actions.sort_unstable();

        let mut review_actions = super::fac_review::doctor_wait_supported_exit_actions();
        review_actions.sort_unstable();

        assert_eq!(enum_actions, review_actions);
    }

    #[test]
    fn test_review_prompt_command_sequence_parses_with_verdict_surface() {
        assert_fac_command_parses(&["fac", "review", "prepare", "--json"]);
        assert_fac_command_parses(&["fac", "review", "findings", "--json"]);
        assert_fac_command_parses(&[
            "fac",
            "review",
            "finding",
            "--type",
            "security",
            "--severity",
            "major",
            "--summary",
            "Unsafe deserialization path",
            "--body",
            "Untrusted bytes reach bincode::deserialize without schema guard.",
            "--risk",
            "RCE",
            "--impact",
            "Compromise of CI runner",
            "--location",
            "src/parser.rs:88",
            "--json",
        ]);
        assert_fac_command_parses(&[
            "fac",
            "review",
            "comment",
            "--type",
            "code-quality",
            "--severity",
            "minor",
            "--body",
            "Legacy compatibility shim still accepted",
            "--json",
        ]);
        assert_fac_command_parses(&["fac", "review", "findings", "--refresh", "--json"]);
        assert_fac_command_parses(&[
            "fac",
            "review",
            "verdict",
            "set",
            "--dimension",
            "security",
            "--verdict",
            "approve",
            "--reason",
            "PASS for 0123456789abcdef0123456789abcdef01234567",
            "--json",
        ]);
        assert_fac_command_parses(&[
            "fac",
            "review",
            "verdict",
            "set",
            "--dimension",
            "code-quality",
            "--verdict",
            "deny",
            "--reason",
            "BLOCKER/MAJOR findings for 0123456789abcdef0123456789abcdef01234567",
            "--json",
        ]);
    }

    #[test]
    fn test_doctor_and_worker_commands_parse() {
        assert_fac_command_parses(&["fac", "doctor", "--fix"]);
        assert_fac_command_parses(&["fac", "worker", "--once"]);
        assert_fac_command_parses(&[
            "fac",
            "worker",
            "--poll-interval-secs",
            "2",
            "--max-jobs",
            "5",
        ]);
    }

    #[test]
    fn test_services_status_json_flag_parses() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "services", "status", "--json"])
            .expect("services status should parse");

        match parsed.subcommand {
            FacSubcommand::Services(args) => match args.subcommand {
                ServicesSubcommand::Status(status_args) => {
                    assert!(status_args.json);
                },
            },
            other => panic!("expected services subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_services_global_json_flag_parses_with_status() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "--json", "services", "status"])
            .expect("global json with services status should parse");

        assert!(parsed.json);
        match parsed.subcommand {
            FacSubcommand::Services(args) => match args.subcommand {
                ServicesSubcommand::Status(status_args) => {
                    assert!(!status_args.json);
                },
            },
            other => panic!("expected services subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_receipts_leaf_json_flags_parse() {
        let list = FacLogsCliHarness::try_parse_from(["fac", "receipts", "list", "--json"])
            .expect("receipts list --json should parse");
        match list.subcommand {
            FacSubcommand::Receipts(args) => match args.subcommand {
                ReceiptSubcommand::List(list_args) => assert!(list_args.json),
                other => panic!("expected receipts list subcommand, got {other:?}"),
            },
            other => panic!("expected receipts command, got {other:?}"),
        }

        let status =
            FacLogsCliHarness::try_parse_from(["fac", "receipts", "status", "job-123", "--json"])
                .expect("receipts status --json should parse");
        match status.subcommand {
            FacSubcommand::Receipts(args) => match args.subcommand {
                ReceiptSubcommand::Status(status_args) => assert!(status_args.json),
                other => panic!("expected receipts status subcommand, got {other:?}"),
            },
            other => panic!("expected receipts command, got {other:?}"),
        }

        let reindex = FacLogsCliHarness::try_parse_from(["fac", "receipts", "reindex", "--json"])
            .expect("receipts reindex --json should parse");
        match reindex.subcommand {
            FacSubcommand::Receipts(args) => match args.subcommand {
                ReceiptSubcommand::Reindex(reindex_args) => assert!(reindex_args.json),
                other => panic!("expected receipts reindex subcommand, got {other:?}"),
            },
            other => panic!("expected receipts command, got {other:?}"),
        }
    }

    #[test]
    fn test_receipts_verify_json_flag_parses() {
        let verify = FacLogsCliHarness::try_parse_from([
            "fac",
            "receipts",
            "verify",
            "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "--json",
        ])
        .expect("receipts verify --json should parse");
        match verify.subcommand {
            FacSubcommand::Receipts(args) => match args.subcommand {
                ReceiptSubcommand::Verify(verify_args) => {
                    assert!(verify_args.json);
                    assert_eq!(
                        verify_args.digest_or_path,
                        "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                    );
                },
                other => panic!("expected receipts verify subcommand, got {other:?}"),
            },
            other => panic!("expected receipts command, got {other:?}"),
        }
    }

    #[test]
    fn test_receipts_merge_json_flag_parses() {
        let merge = FacLogsCliHarness::try_parse_from([
            "fac",
            "receipts",
            "merge",
            "--from",
            "/tmp/source",
            "--into",
            "/tmp/target",
            "--json",
        ])
        .expect("receipts merge --json should parse");
        match merge.subcommand {
            FacSubcommand::Receipts(args) => match args.subcommand {
                ReceiptSubcommand::Merge(merge_args) => {
                    assert!(merge_args.json);
                    assert_eq!(merge_args.from, std::path::PathBuf::from("/tmp/source"));
                    assert_eq!(merge_args.into, std::path::PathBuf::from("/tmp/target"));
                },
                other => panic!("expected receipts merge subcommand, got {other:?}"),
            },
            other => panic!("expected receipts command, got {other:?}"),
        }
    }

    #[test]
    fn test_job_cancel_json_flag_parses() {
        let parsed =
            FacLogsCliHarness::try_parse_from(["fac", "job", "cancel", "job-123", "--json"])
                .expect("job cancel --json should parse");
        match parsed.subcommand {
            FacSubcommand::Job(args) => match args.subcommand {
                JobSubcommand::Cancel(cancel_args) => assert!(cancel_args.json),
                JobSubcommand::Show(_) => panic!("expected cancel subcommand, got show"),
            },
            other => panic!("expected job command, got {other:?}"),
        }
    }

    // =========================================================================
    // truncate_str UTF-8 safety tests (MINOR finding fix)
    // =========================================================================

    #[test]
    fn test_truncate_str_ascii_no_truncation() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_str_ascii_truncated() {
        assert_eq!(truncate_str("hello world", 7), "hello..");
    }

    #[test]
    fn test_truncate_str_multibyte_no_panic() {
        // Multi-byte UTF-8 characters should not cause panic.
        let s = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}"; // 4 emoji characters
        let result = truncate_str(s, 3);
        assert_eq!(result.chars().count(), 3); // 1 char + ".."
        assert!(result.ends_with(".."));
    }

    #[test]
    fn test_truncate_str_exact_length() {
        assert_eq!(truncate_str("abc", 3), "abc");
    }

    #[test]
    fn test_truncate_str_max_len_two() {
        assert_eq!(truncate_str("abcdef", 2), "ab");
    }

    #[test]
    fn test_truncate_str_max_len_zero() {
        assert_eq!(truncate_str("abc", 0), "");
    }

    /// Integration test: exported bundle can be re-imported successfully.
    ///
    /// This proves the export/import pair forms a usable RFC-0028/0029 harness
    /// (BLOCKER-3 fix). The test constructs a valid receipt, writes it to the
    /// receipt store, runs the export path, then imports the exported manifest.
    #[test]
    fn test_bundle_export_import_round_trip() {
        use apm2_core::fac::evidence_bundle::EVIDENCE_BUNDLE_ENVELOPE_SCHEMA;
        use apm2_core::fac::{
            BlobStore, BudgetAdmissionTrace, ChannelBoundaryTrace, FacJobOutcome, FacJobReceiptV1,
            QueueAdmissionTrace, compute_job_receipt_content_hash,
        };

        let home = tempfile::tempdir().expect("temp dir");
        let _home_guard = Apm2HomeGuard::new(home.path());
        let fac_root = home.path().join("private").join("fac");
        let receipts_dir = fac_root.join("receipts");
        std::fs::create_dir_all(&receipts_dir).expect("create receipts dir");

        let blob_store = BlobStore::new(&fac_root);
        let receipt_blob = b"round trip receipt blob".to_vec();
        let receipt_blob_hash = blob_store
            .store(&receipt_blob)
            .expect("store receipt blob in CAS");
        let job_spec_blob = b"round trip job spec blob".to_vec();
        let job_spec_blob_hash = blob_store
            .store(&job_spec_blob)
            .expect("store job spec blob");

        // The receipt's `content_hash` field references a blob stored in the
        // CAS (plain BLAKE3), used by the export function to retrieve the blob.
        // The receipt *file* is named by `compute_job_receipt_content_hash`
        // (domain-separated BLAKE3 of canonical bytes), which the fallback
        // scan verifies for integrity (MAJOR-1 fix, TCK-00564 round 8).
        // These two hashes are intentionally different: `content_hash` is a
        // CAS reference, while the filename is the integrity digest.
        let receipt = FacJobReceiptV1 {
            schema: "apm2.fac.job_receipt.v1".to_string(),
            receipt_id: "test-rt-receipt".to_string(),
            job_id: "test-rt-job".to_string(),
            job_spec_digest: format!("b3-256:{}", hex::encode(job_spec_blob_hash)),
            policy_hash: Some("b3-256:".to_string() + &"ab".repeat(32)),
            canonicalizer_tuple_digest: Some("b3-256:".to_string() + &"cd".repeat(32)),
            outcome: FacJobOutcome::Completed,
            reason: "round trip test".to_string(),
            rfc0028_channel_boundary: Some(ChannelBoundaryTrace {
                passed: true,
                defect_count: 0,
                defect_classes: vec![],
                token_fac_policy_hash: None,
                token_canonicalizer_tuple_digest: None,
                token_boundary_id: None,
                token_issued_at_tick: None,
                token_expiry_tick: None,
            }),
            eio29_queue_admission: Some(QueueAdmissionTrace {
                verdict: "Allow".to_string(),
                queue_lane: "consume".to_string(),
                defect_reason: None,
                cost_estimate_ticks: None,
            }),
            eio29_budget_admission: Some(BudgetAdmissionTrace {
                verdict: "Allow".to_string(),
                reason: None,
            }),
            timestamp_secs: 1_700_000_000,
            content_hash: "b3-256:".to_string() + &hex::encode(receipt_blob_hash),
            ..Default::default()
        };

        // Name the receipt file by the domain-separated integrity hash so that
        // the fallback scan's verify_receipt_integrity check passes.
        let integrity_hash = compute_job_receipt_content_hash(&receipt);
        let receipt_file = receipts_dir.join(format!("{integrity_hash}.json"));
        let bytes = serde_json::to_vec_pretty(&receipt).expect("serialize receipt for store");
        std::fs::write(&receipt_file, bytes).expect("write receipt to store");

        // Build a well-formed export config (same logic as production path).
        build_export_config_from_receipt(&receipt)
            .expect("export config should succeed with valid digests");

        let output_dir = home.path().join("bundle-export");
        let export_args = BundleExportArgs {
            job_id: "test-rt-job".to_string(),
            output_dir: Some(output_dir.clone()),
            json: false,
        };
        let export_exit = run_bundle_export(&export_args, false);
        assert_eq!(
            export_exit,
            exit_codes::SUCCESS,
            "bundle export should succeed"
        );

        let manifest_path = output_dir.join("manifest.json");
        let envelope_path = output_dir.join("envelope.json");
        assert!(manifest_path.exists(), "export should write manifest.json");
        assert!(envelope_path.exists(), "export should write envelope.json");

        let receipt_blob_hex = &receipt.content_hash["b3-256:".len()..];
        let job_spec_blob_hex = &receipt.job_spec_digest["b3-256:".len()..];
        assert!(
            output_dir.join(format!("{receipt_blob_hex}.blob")).exists(),
            "export should include receipt content blob"
        );
        assert!(
            output_dir
                .join(format!("{job_spec_blob_hex}.blob"))
                .exists(),
            "export should include job spec blob"
        );

        // Confirm the exported envelope schema matches canonical release schema.
        let envelope = std::fs::read_to_string(&envelope_path).expect("read exported envelope");
        let envelope_json: serde_json::Value =
            serde_json::from_str(&envelope).expect("parse exported envelope json");
        assert_eq!(envelope_json["schema"], EVIDENCE_BUNDLE_ENVELOPE_SCHEMA);

        let import_args = BundleImportArgs {
            path: manifest_path,
            json: false,
        };
        let import_exit = run_bundle_import(&import_args, false);
        assert_eq!(
            import_exit,
            exit_codes::SUCCESS,
            "bundle import should succeed"
        );
    }

    // =========================================================================
    // Fail-closed tests for malformed policy digests (MAJOR finding fix)
    // =========================================================================

    /// Missing `policy_hash` must produce `MalformedPolicyDigest` error.
    #[test]
    fn test_build_export_config_missing_policy_hash_fails() {
        use apm2_core::fac::{FacJobOutcome, FacJobReceiptV1};

        let receipt = FacJobReceiptV1 {
            schema: "apm2.fac.job_receipt.v1".to_string(),
            receipt_id: "test-missing-ph".to_string(),
            job_id: "test-job".to_string(),
            job_spec_digest: "b3-256:".to_string() + &"ab".repeat(32),
            policy_hash: None, // absent
            canonicalizer_tuple_digest: Some(format!("b3-256:{}", "cd".repeat(32))),
            outcome: FacJobOutcome::Completed,
            reason: "test".to_string(),
            timestamp_secs: 1_700_000_000,
            content_hash: String::new(),
            ..Default::default()
        };

        let result = build_export_config_from_receipt(&receipt);
        assert!(result.is_err(), "missing policy_hash must fail");
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("policy_hash"),
            "error must mention the field: {msg}"
        );
    }

    /// Missing `canonicalizer_tuple_digest` must produce
    /// `MalformedPolicyDigest` error.
    #[test]
    fn test_build_export_config_missing_canonicalizer_digest_fails() {
        use apm2_core::fac::{FacJobOutcome, FacJobReceiptV1};

        let receipt = FacJobReceiptV1 {
            schema: "apm2.fac.job_receipt.v1".to_string(),
            receipt_id: "test-missing-ctd".to_string(),
            job_id: "test-job".to_string(),
            job_spec_digest: "b3-256:".to_string() + &"ab".repeat(32),
            policy_hash: Some(format!("b3-256:{}", "ab".repeat(32))),
            canonicalizer_tuple_digest: None, // absent
            outcome: FacJobOutcome::Completed,
            reason: "test".to_string(),
            timestamp_secs: 1_700_000_000,
            content_hash: String::new(),
            ..Default::default()
        };

        let result = build_export_config_from_receipt(&receipt);
        assert!(
            result.is_err(),
            "missing canonicalizer_tuple_digest must fail"
        );
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("canonicalizer_tuple_digest"),
            "error must mention the field: {msg}"
        );
    }

    /// Malformed (non-hex) `policy_hash` must produce `MalformedPolicyDigest`
    /// error.
    #[test]
    fn test_build_export_config_malformed_hex_policy_hash_fails() {
        use apm2_core::fac::{FacJobOutcome, FacJobReceiptV1};

        let receipt = FacJobReceiptV1 {
            schema: "apm2.fac.job_receipt.v1".to_string(),
            receipt_id: "test-bad-hex-ph".to_string(),
            job_id: "test-job".to_string(),
            job_spec_digest: "b3-256:".to_string() + &"ab".repeat(32),
            policy_hash: Some("b3-256:not_valid_hex!!".to_string()),
            canonicalizer_tuple_digest: Some(format!("b3-256:{}", "cd".repeat(32))),
            outcome: FacJobOutcome::Completed,
            reason: "test".to_string(),
            timestamp_secs: 1_700_000_000,
            content_hash: String::new(),
            ..Default::default()
        };

        let result = build_export_config_from_receipt(&receipt);
        assert!(result.is_err(), "non-hex policy_hash must fail");
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("policy_hash") && msg.contains("hex"),
            "error must mention field and hex failure: {msg}"
        );
    }

    /// Wrong-length `policy_hash` (valid hex but not 32 bytes) must fail.
    #[test]
    fn test_build_export_config_wrong_length_policy_hash_fails() {
        use apm2_core::fac::{FacJobOutcome, FacJobReceiptV1};

        let receipt = FacJobReceiptV1 {
            schema: "apm2.fac.job_receipt.v1".to_string(),
            receipt_id: "test-short-ph".to_string(),
            job_id: "test-job".to_string(),
            job_spec_digest: "b3-256:".to_string() + &"ab".repeat(32),
            policy_hash: Some("b3-256:aabb".to_string()), // only 2 bytes
            canonicalizer_tuple_digest: Some(format!("b3-256:{}", "cd".repeat(32))),
            outcome: FacJobOutcome::Completed,
            reason: "test".to_string(),
            timestamp_secs: 1_700_000_000,
            content_hash: String::new(),
            ..Default::default()
        };

        let result = build_export_config_from_receipt(&receipt);
        assert!(result.is_err(), "wrong-length policy_hash must fail");
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("policy_hash") && msg.contains("32 bytes"),
            "error must mention field and expected length: {msg}"
        );
    }

    // =========================================================================
    // MAJOR security fix: job_id path traversal prevention tests
    // =========================================================================

    /// TCK-00527: Empty `job_id` must be rejected.
    #[test]
    fn test_validate_job_id_rejects_empty() {
        let result = validate_job_id_for_path("");
        assert!(result.is_err(), "empty job_id must be rejected");
        assert!(
            result.unwrap_err().contains("empty"),
            "error must mention empty"
        );
    }

    /// TCK-00527: Absolute path `job_id` must be rejected.
    #[test]
    fn test_validate_job_id_rejects_absolute_path() {
        let result = validate_job_id_for_path("/tmp/evil");
        assert!(result.is_err(), "absolute path job_id must be rejected");
        assert!(
            result.unwrap_err().contains("absolute"),
            "error must mention absolute path"
        );
    }

    /// TCK-00527: Backslash absolute path must be rejected.
    #[test]
    fn test_validate_job_id_rejects_backslash_absolute() {
        let result = validate_job_id_for_path("\\tmp\\evil");
        assert!(
            result.is_err(),
            "backslash absolute path job_id must be rejected"
        );
    }

    /// TCK-00527: Path traversal via `..` must be rejected.
    #[test]
    fn test_validate_job_id_rejects_dotdot_traversal() {
        for traversal in &["../../../etc/passwd", "..%2F..%2Fetc", "foo/../bar", ".."] {
            let result = validate_job_id_for_path(traversal);
            assert!(
                result.is_err(),
                "path traversal job_id {traversal:?} must be rejected"
            );
        }
    }

    /// TCK-00527: Job IDs containing path separators must be rejected.
    #[test]
    fn test_validate_job_id_rejects_path_separators() {
        for bad in &["a/b", "a\\b", "foo/bar/baz"] {
            let result = validate_job_id_for_path(bad);
            assert!(
                result.is_err(),
                "job_id with path separator {bad:?} must be rejected"
            );
        }
    }

    /// TCK-00527: Job IDs with special characters must be rejected.
    #[test]
    fn test_validate_job_id_rejects_special_chars() {
        for bad in &["a;b", "a b", "a\x00b", "a*b", "a?b", "$HOME"] {
            let result = validate_job_id_for_path(bad);
            assert!(
                result.is_err(),
                "job_id with special chars {bad:?} must be rejected"
            );
        }
    }

    /// TCK-00527: Valid job IDs must be accepted.
    #[test]
    fn test_validate_job_id_accepts_valid_ids() {
        for valid in &[
            "abc-123",
            "ABC_def",
            "job-42",
            "a",
            "test-rt-job",
            "fac.job.2026-02-15",
        ] {
            let result = validate_job_id_for_path(valid);
            assert!(
                result.is_ok(),
                "valid job_id {valid:?} must be accepted: {:?}",
                result.unwrap_err()
            );
        }
    }

    /// Regression test: receipt list deterministic sorting (MAJOR finding).
    /// Verifies timestamp-desc / `content_hash`-asc ordering with equal
    /// timestamps.
    #[test]
    fn test_receipt_list_sorting_deterministic() {
        use apm2_core::fac::{FacJobOutcome, ReceiptHeaderV1};

        let h1 = ReceiptHeaderV1 {
            job_id: "job1".to_string(),
            content_hash: "hash_b".to_string(),
            outcome: FacJobOutcome::Completed,
            timestamp_secs: 100,
            queue_lane: Some("lane".to_string()),
            unsafe_direct: false,
        };
        let h2 = ReceiptHeaderV1 {
            job_id: "job2".to_string(),
            content_hash: "hash_a".to_string(),
            outcome: FacJobOutcome::Completed,
            timestamp_secs: 100, // Same timestamp as h1
            queue_lane: Some("lane".to_string()),
            unsafe_direct: false,
        };
        let h3 = ReceiptHeaderV1 {
            job_id: "job3".to_string(),
            content_hash: "hash_c".to_string(),
            outcome: FacJobOutcome::Completed,
            timestamp_secs: 200, // Newer
            queue_lane: Some("lane".to_string()),
            unsafe_direct: false,
        };

        let mut headers = Vec::from([h1, h2, h3]);

        // Sort: timestamp desc, hash asc
        headers.sort_by(|a, b| {
            b.timestamp_secs
                .cmp(&a.timestamp_secs)
                .then_with(|| a.content_hash.cmp(&b.content_hash))
        });

        assert_eq!(headers[0].job_id, "job3"); // timestamp 200 (most recent)
        assert_eq!(headers[1].job_id, "job2"); // timestamp 100, hash_a (asc)
        assert_eq!(headers[2].job_id, "job1"); // timestamp 100, hash_b (asc)
    }

    /// Regression test: `--since` inclusive filtering boundary (MINOR finding).
    /// Verifies that receipts with `timestamp_secs` == since are included.
    #[test]
    fn test_receipt_list_since_inclusive_boundary() {
        use apm2_core::fac::{FacJobOutcome, ReceiptHeaderV1};

        let headers = vec![
            ReceiptHeaderV1 {
                job_id: "old".to_string(),
                content_hash: "hash_old".to_string(),
                outcome: FacJobOutcome::Completed,
                timestamp_secs: 99,
                queue_lane: None,
                unsafe_direct: false,
            },
            ReceiptHeaderV1 {
                job_id: "boundary".to_string(),
                content_hash: "hash_boundary".to_string(),
                outcome: FacJobOutcome::Completed,
                timestamp_secs: 100,
                queue_lane: None,
                unsafe_direct: false,
            },
            ReceiptHeaderV1 {
                job_id: "new".to_string(),
                content_hash: "hash_new".to_string(),
                outcome: FacJobOutcome::Completed,
                timestamp_secs: 200,
                queue_lane: None,
                unsafe_direct: false,
            },
        ];

        let since = 100u64;
        let filtered: Vec<_> = headers
            .into_iter()
            .filter(|h| h.timestamp_secs >= since)
            .collect();

        // Should include boundary (100) and new (200), exclude old (99).
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|h| h.job_id == "boundary"));
        assert!(filtered.iter().any(|h| h.job_id == "new"));
        assert!(!filtered.iter().any(|h| h.job_id == "old"));
    }

    // =========================================================================
    // Lane Mark-Corrupt Command Tests (TCK-00570)
    // =========================================================================

    #[test]
    fn test_lane_mark_corrupt_cli_parses() {
        assert_fac_command_parses(&[
            "test",
            "lane",
            "mark-corrupt",
            "lane-00",
            "--reason",
            "suspected data corruption",
        ]);
    }

    #[test]
    fn test_lane_mark_corrupt_cli_parses_with_receipt_digest() {
        assert_fac_command_parses(&[
            "test",
            "lane",
            "mark-corrupt",
            "lane-00",
            "--reason",
            "cleanup failure",
            "--receipt-digest",
            "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        ]);
    }

    #[test]
    fn test_lane_mark_corrupt_creates_marker() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root.clone()).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";
        // Verify lane starts IDLE.
        let status = manager.lane_status(lane_id).expect("initial lane status");
        assert_eq!(status.state, LaneState::Idle);

        let exit_code = run_lane_mark_corrupt_with_manager(
            &manager,
            &LaneMarkCorruptArgs {
                lane_id: lane_id.to_string(),
                reason: "operator maintenance".to_string(),
                receipt_digest: None,
                json: true,
            },
            true,
        );
        assert_eq!(exit_code, exit_codes::SUCCESS, "mark-corrupt must succeed");

        // Verify marker exists with correct content.
        let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect("load marker")
            .expect("marker must be present");
        assert_eq!(marker.lane_id, lane_id);
        assert_eq!(marker.reason, "operator maintenance");
        assert!(marker.cleanup_receipt_digest.is_none());
        assert!(!marker.detected_at.is_empty());

        // Verify lane status shows CORRUPT.
        let status = manager
            .lane_status(lane_id)
            .expect("lane status after mark-corrupt");
        assert_eq!(status.state, LaneState::Corrupt);
        assert_eq!(
            status.corrupt_reason.as_deref(),
            Some("operator maintenance")
        );
    }

    #[test]
    fn test_lane_mark_corrupt_with_receipt_digest() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root.clone()).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-01";
        let digest =
            "b3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let exit_code = run_lane_mark_corrupt_with_manager(
            &manager,
            &LaneMarkCorruptArgs {
                lane_id: lane_id.to_string(),
                reason: "cleanup failed".to_string(),
                receipt_digest: Some(digest.clone()),
                json: true,
            },
            true,
        );
        assert_eq!(exit_code, exit_codes::SUCCESS);

        let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect("load marker")
            .expect("marker must be present");
        assert_eq!(
            marker.cleanup_receipt_digest.as_deref(),
            Some(digest.as_str())
        );
    }

    #[test]
    fn test_lane_mark_corrupt_rejects_malformed_digest() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        // Missing prefix
        let exit_code = run_lane_mark_corrupt_with_manager(
            &manager,
            &LaneMarkCorruptArgs {
                lane_id: "lane-00".to_string(),
                reason: "test".to_string(),
                receipt_digest: Some("not-a-digest".to_string()),
                json: true,
            },
            true,
        );
        assert_eq!(
            exit_code,
            exit_codes::VALIDATION_ERROR,
            "malformed digest must fail validation"
        );

        // Wrong hex length
        let exit_code = run_lane_mark_corrupt_with_manager(
            &manager,
            &LaneMarkCorruptArgs {
                lane_id: "lane-00".to_string(),
                reason: "test".to_string(),
                receipt_digest: Some("b3-256:deadbeef".to_string()),
                json: true,
            },
            true,
        );
        assert_eq!(
            exit_code,
            exit_codes::VALIDATION_ERROR,
            "short digest must fail validation"
        );

        // Uppercase hex
        let exit_code = run_lane_mark_corrupt_with_manager(
            &manager,
            &LaneMarkCorruptArgs {
                lane_id: "lane-00".to_string(),
                reason: "test".to_string(),
                receipt_digest: Some(
                    "b3-256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
                json: true,
            },
            true,
        );
        assert_eq!(
            exit_code,
            exit_codes::VALIDATION_ERROR,
            "uppercase hex digest must fail validation"
        );
    }

    #[test]
    fn test_lane_mark_corrupt_refuses_already_corrupt() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root.clone()).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";

        // Mark corrupt the first time.
        let first = run_lane_mark_corrupt_with_manager(
            &manager,
            &LaneMarkCorruptArgs {
                lane_id: lane_id.to_string(),
                reason: "first mark".to_string(),
                receipt_digest: None,
                json: true,
            },
            true,
        );
        assert_eq!(first, exit_codes::SUCCESS);

        // Attempt to mark corrupt again -- must be refused.
        let second = run_lane_mark_corrupt_with_manager(
            &manager,
            &LaneMarkCorruptArgs {
                lane_id: lane_id.to_string(),
                reason: "second mark".to_string(),
                receipt_digest: None,
                json: true,
            },
            true,
        );
        assert_eq!(
            second,
            exit_codes::VALIDATION_ERROR,
            "mark-corrupt on already-corrupt lane must fail with VALIDATION_ERROR"
        );

        // Verify the original marker is preserved (not overwritten).
        let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect("load marker")
            .expect("marker must be present");
        assert_eq!(marker.reason, "first mark");
    }

    #[test]
    fn test_lane_mark_corrupt_reason_length_validation() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        // Create a reason that exceeds MAX_STRING_LENGTH (512).
        let long_reason = "x".repeat(apm2_core::fac::lane::MAX_STRING_LENGTH + 1);
        let exit_code = run_lane_mark_corrupt_with_manager(
            &manager,
            &LaneMarkCorruptArgs {
                lane_id: "lane-00".to_string(),
                reason: long_reason,
                receipt_digest: None,
                json: true,
            },
            true,
        );
        assert_eq!(
            exit_code,
            exit_codes::VALIDATION_ERROR,
            "oversized reason must fail validation"
        );
    }

    #[test]
    fn test_lane_mark_corrupt_then_doctor_reset_clears() {
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root.clone()).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        let lane_id = "lane-00";

        // Mark corrupt.
        let mark_exit = run_lane_mark_corrupt_with_manager(
            &manager,
            &LaneMarkCorruptArgs {
                lane_id: lane_id.to_string(),
                reason: "mark then reset".to_string(),
                receipt_digest: None,
                json: true,
            },
            true,
        );
        assert_eq!(mark_exit, exit_codes::SUCCESS);

        // Reset the lane through doctor remediation logic.
        let reset = doctor_reset_lane_once(&manager, lane_id);
        assert!(reset.is_ok(), "doctor reset should succeed: {reset:?}");

        // Marker should be cleared.
        assert!(
            LaneCorruptMarkerV1::load(&fac_root, lane_id)
                .expect("load marker")
                .is_none(),
            "corrupt marker must be cleared after reset"
        );
    }

    #[test]
    fn test_lane_mark_corrupt_worker_refuses_corrupt_lane() {
        // This test validates that the existing worker lane-acquisition logic
        // (tested in fac_worker tests) correctly refuses corrupt-marked lanes.
        // We verify the foundational behavior here: a corrupt marker on disk
        // causes `lane_status` to report CORRUPT.
        let home = tempfile::tempdir().expect("temp dir");
        let fac_root = home.path().join("private").join("fac");

        let manager = LaneManager::new(fac_root.clone()).expect("create lane manager");
        manager
            .ensure_directories()
            .expect("create lanes and directories");

        // Mark all lanes corrupt.
        for lane_id in LaneManager::default_lane_ids() {
            let marker = LaneCorruptMarkerV1 {
                schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
                lane_id: lane_id.clone(),
                reason: "all lanes corrupt".to_string(),
                cleanup_receipt_digest: None,
                detected_at: "2026-02-18T00:00:00Z".to_string(),
            };
            marker.persist(&fac_root).expect("persist marker");
        }

        // All lanes should report CORRUPT.
        let statuses = manager.all_lane_statuses().expect("all lane statuses");
        for status in &statuses {
            assert_eq!(
                status.state,
                LaneState::Corrupt,
                "lane {} must be CORRUPT",
                status.lane_id
            );
        }
    }
}
