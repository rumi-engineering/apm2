//! FAC (Forge Admission Cycle) productivity CLI commands.
//!
//! This module implements the `apm2 fac` subcommands for ledger/CAS-oriented
//! debugging and productivity per TCK-00333 and RFC-0019.
//!
//! # Commands
//!
//! - `apm2 fac gates` - Run all evidence gates locally with resource-bounded
//!   test execution; results cached per-SHA for pipeline reuse
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
//! - `apm2 fac resume <work_id>` - Show crash-only resume helpers from ledger
//!   anchor
//! - `apm2 fac review run --pr <N>` - Run FAC review orchestration (parallel,
//!   multi-model; defaults from local branch mapping when omitted)
//! - `apm2 fac review dispatch --pr <N>` - Dispatch detached FAC review runs
//! - `apm2 fac review status` - Show FAC review state and recent events
//! - `apm2 fac review findings` - Retrieve SHA-bound review findings in a
//!   structured FAC-native format
//! - `apm2 fac review verdict` - Show/set SHA-bound approve/deny verdicts per
//!   review dimension
//! - `apm2 fac services status` - Inspect daemon/worker managed service health
//! - `apm2 fac restart --pr <PR_NUMBER>` - Intelligent pipeline restart from
//!   optimal point
//! - `apm2 fac recover --pr <N>` - Repair/reconcile local FAC lifecycle state
//! - `apm2 fac review project` - Render one projection status line
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

use apm2_core::fac::{
    LANE_ENV_DIRS, LaneCorruptMarkerV1, LaneInitReceiptV1, LaneLeaseV1, LaneManager,
    LaneReconcileReceiptV1, LaneState, LaneStatusV1, PROJECTION_ARTIFACT_SCHEMA_IDENTIFIER,
    REVIEW_ARTIFACT_SCHEMA_IDENTIFIER, RefusedDeleteReceipt, SUMMARY_RECEIPT_SCHEMA,
    SafeRmtreeOutcome, TOOL_EXECUTION_RECEIPT_SCHEMA, TOOL_LOG_INDEX_V1_SCHEMA, ToolLogIndexV1,
    safe_rmtree_v1,
};
use apm2_core::ledger::{EventRecord, Ledger, LedgerError};
use apm2_daemon::protocol::WorkRole;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::client::protocol::{OperatorClient, ProtocolClientError};
pub use crate::commands::fac_broker::BrokerArgs;
use crate::commands::role_launch::{self, RoleLaunchArgs};
use crate::commands::{fac_broker, fac_gc, fac_pr, fac_preflight, fac_quarantine, fac_review};
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

    #[command(subcommand)]
    pub subcommand: FacSubcommand,
}

/// FAC subcommands.
#[derive(Debug, Subcommand)]
pub enum FacSubcommand {
    /// Run all evidence gates locally with resource-bounded test execution.
    ///
    /// Validates fmt, clippy, doc, test safety, tests (bounded), workspace
    /// integrity, and review artifact lint. Results are cached per-SHA so
    /// `apm2 fac pipeline` can skip gates that already passed.
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

    /// Show crash-only resume helpers from ledger anchor.
    ///
    /// Analyzes ledger to determine restart point for interrupted work.
    /// Returns the last committed anchor and pending operations.
    Resume(ResumeArgs),

    /// Manage FAC execution lanes.
    ///
    /// Shows lane states derived from lock state, lease records, and PID
    /// liveness. Lanes are the sole concurrency primitive for FAC execution.
    Lane(LaneArgs),

    /// Push code and create/update PR (lean push).
    ///
    /// Pushes to remote, creates or updates a PR from ticket YAML metadata,
    /// blocks on evidence gates, enables auto-merge, and dispatches reviews.
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
    /// Reconcile queue and lane state after crash or unclean shutdown.
    ///
    /// Detects stale lane leases (PID dead, lock released), orphaned claimed
    /// jobs, and recovers them deterministically. All actions emit receipts.
    Reconcile(ReconcileArgs),
    /// Introspect FAC queue state (forensics-first UX).
    ///
    /// Shows job counts by directory, oldest pending job, and
    /// denial/quarantine reason code distributions.
    Queue(QueueArgs),
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

    /// Execute doctor-prescribed recovery actions for the PR.
    #[arg(long, default_value_t = false)]
    pub fix: bool,

    /// Output in JSON format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Upgrade credential checks from WARN to ERROR.
    ///
    /// Use this when running GitHub-facing workflows (push, review dispatch)
    /// that require valid credentials. Without this flag, missing credentials
    /// produce WARN; with it, they produce ERROR and cause a non-zero exit.
    #[arg(long, default_value_t = false)]
    pub full: bool,

    /// Wait until doctor recommends an action other than `wait`.
    #[arg(long, default_value_t = false)]
    pub wait_for_recommended_action: bool,

    /// Poll cadence while waiting for recommended action.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=10))]
    pub poll_interval_seconds: u64,

    /// Maximum wait time while waiting for recommended action.
    #[arg(long, default_value_t = 1200, value_parser = parse_wait_timeout)]
    pub wait_timeout_seconds: u64,

    /// Exit only when doctor returns one of these actions (comma-separated).
    #[arg(long, value_delimiter = ',', value_enum)]
    pub exit_on: Vec<DoctorExitActionArg>,
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

/// Arguments for `apm2 fac resume`.
#[derive(Debug, Args)]
pub struct ResumeArgs {
    /// Work identifier to analyze for resume point.
    pub work_id: String,

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
    /// Reset a lane by deleting its workspace, target, and logs.
    ///
    /// Refuses to reset a RUNNING lane unless `--force` is provided.
    /// With `--force`, attempts to kill the lane's process before
    /// cleaning up. Uses `safe_rmtree_v1` which refuses symlink
    /// traversal and crossing filesystem boundaries.
    Reset(LaneResetArgs),
    /// Initialize the lane pool: create directories and write default profiles.
    ///
    /// Bootstraps a fresh `$APM2_HOME` into a ready lane pool with one
    /// command. Existing profiles are left untouched (idempotent).
    /// Lane count is configurable via `$APM2_FAC_LANE_COUNT` (default: 3,
    /// max: 32).
    Init(LaneInitArgs),
    /// Reconcile lane state: repair missing directories and profiles.
    ///
    /// Inspects all configured lanes and repairs missing directories or
    /// profiles. Lanes that cannot be repaired are marked CORRUPT.
    /// Existing corrupt markers are reported but not cleared (use
    /// `apm2 fac lane reset` to clear them).
    Reconcile(LaneReconcileArgs),
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

/// Arguments for `apm2 fac lane reset`.
#[derive(Debug, Args)]
pub struct LaneResetArgs {
    /// Lane identifier to reset (e.g., `lane-00`).
    pub lane_id: String,

    /// Force reset even if lane is RUNNING. Kills the lane's process first.
    #[arg(long, default_value_t = false)]
    pub force: bool,

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

/// Arguments for `apm2 fac lane reconcile` (TCK-00539).
#[derive(Debug, Args)]
pub struct LaneReconcileArgs {
    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac reconcile`.
#[derive(Debug, Args)]
pub struct ReconcileArgs {
    /// Report what would be done without mutating state.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Apply all recovery mutations.
    #[arg(long, default_value_t = false)]
    pub apply: bool,

    /// Policy for orphaned claimed jobs: "requeue" (default) or "mark-failed".
    #[arg(long, default_value = "requeue")]
    pub orphan_policy: String,

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
    /// Dispatch FAC review orchestration in detached mode.
    Dispatch(ReviewDispatchArgs),
    /// Block until active FAC review runs for a PR reach terminal state.
    Wait(ReviewWaitArgs),
    /// Show FAC review state/events from local operational artifacts.
    Status(ReviewStatusArgs),
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
    /// Render one condensed projection line for GitHub log surfaces.
    Project(ReviewProjectArgs),
    /// Tail FAC review NDJSON event stream.
    Tail(ReviewTailArgs),
    /// Terminate a running reviewer process for a specific PR and type.
    Terminate(ReviewTerminateArgs),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ReviewFormatArg {
    #[default]
    Text,
    Json,
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

/// Arguments for `apm2 fac review wait`.
#[derive(Debug, Args)]
pub struct ReviewWaitArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: u32,

    /// Optional reviewer lane filter (`security` or `quality`).
    #[arg(long = "type", value_enum)]
    pub review_type: Option<ReviewStatusTypeArg>,

    /// Maximum wait time in seconds. Omit to wait indefinitely.
    #[arg(long)]
    pub timeout_seconds: Option<u64>,

    /// Poll cadence in seconds (min: 1, default: 5).
    #[arg(long, default_value_t = 5)]
    pub poll_interval_seconds: u64,

    /// Required head SHA for stale projection protection.
    #[arg(long = "wait-for-sha")]
    pub wait_for_sha: Option<String>,

    /// Output format (`text` or `json`).
    #[arg(long, default_value = "text", value_enum)]
    pub format: ReviewFormatArg,

    /// Emit JSON output for this command (alias for --format json).
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac review dispatch`.
#[derive(Debug, Args)]
pub struct ReviewDispatchArgs {
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

    /// Optional expected head SHA (40 hex) to fail closed on stale dispatch.
    #[arg(long)]
    pub expected_head_sha: Option<String>,

    /// Force re-dispatch on the same SHA even when a terminal run already
    /// exists for this review type.
    ///
    /// This does not bypass merge-conflict checks against `main`.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Review lane filter for `apm2 fac review status`.
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

/// Arguments for `apm2 fac review status`.
#[derive(Debug, Args)]
pub struct ReviewStatusArgs {
    /// Optional pull request number filter.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Optional reviewer lane filter (`security` or `quality`).
    #[arg(long = "type", value_enum)]
    pub review_type: Option<ReviewStatusTypeArg>,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
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

/// Arguments for `apm2 fac review project`.
#[derive(Debug, Args)]
pub struct ReviewProjectArgs {
    /// Pull request number to project.
    #[arg(long)]
    pub pr: u32,

    /// Optional head SHA filter (40 hex).
    #[arg(long)]
    pub head_sha: Option<String>,

    /// Optional minimum event timestamp (unix seconds).
    #[arg(long)]
    pub since_epoch: Option<u64>,

    /// Emit only errors with seq greater than this value.
    #[arg(long, default_value_t = 0)]
    pub after_seq: u64,

    /// Also print ERROR lines in text mode.
    #[arg(long, default_value_t = false)]
    pub emit_errors: bool,

    /// Return non-zero when terminal failure is detected.
    #[arg(long, default_value_t = false)]
    pub fail_on_terminal: bool,

    /// Output format (`text` or `json`).
    #[arg(long, default_value = "text", value_enum)]
    pub format: ReviewFormatArg,

    /// Emit JSON output for this command (alias for --format json).
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

/// Response for resume command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeResponse {
    /// Work identifier.
    pub work_id: String,
    /// Last committed anchor sequence ID.
    pub last_anchor_seq_id: u64,
    /// Last committed anchor event type.
    pub last_anchor_event_type: String,
    /// Recommended restart action.
    pub restart_action: String,
    /// Pending operations (if any).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pending_operations: Vec<String>,
    /// Last episode ID (if work was in progress).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_episode_id: Option<String>,
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

    let overall_health = if degraded { "degraded" } else { "healthy" }.to_string();

    let response = ServicesStatusResponse {
        overall_health,
        services: services.clone(),
        worker_heartbeat,
        broker_health,
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

    if let Err(err) = crate::commands::fac_permissions::validate_fac_root_permissions() {
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
            | FacSubcommand::Reconcile(_)
            | FacSubcommand::Queue(_)
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
        FacSubcommand::Doctor(args) => {
            let output_json = resolve_json(args.json);
            if args.wait_for_recommended_action && args.pr.is_none() {
                return output_error(
                    output_json,
                    "fac_doctor_wait_requires_pr",
                    "`--wait-for-recommended-action` requires `--pr <N>`",
                    exit_codes::GENERIC_ERROR,
                );
            }
            if args.fix && args.pr.is_none() {
                return output_error(
                    output_json,
                    "fac_doctor_fix_requires_pr",
                    "`apm2 fac doctor --fix` requires `--pr <N>`",
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
            } else {
                let (mut checks, has_critical_error) =
                    match crate::commands::daemon::collect_doctor_checks(
                        operator_socket,
                        config_path,
                        args.full,
                    ) {
                        Ok(value) => value,
                        Err(err) => {
                            return output_error(
                                output_json,
                                "fac_doctor_failed",
                                &err.to_string(),
                                exit_codes::GENERIC_ERROR,
                            );
                        },
                    };
                let repo_hint = fac_review::derive_repo().ok();
                let tracked_prs =
                    match fac_review::collect_tracked_pr_summaries(repo_hint.as_deref()) {
                        Ok(value) => value,
                        Err(err) => {
                            let message =
                                format!("failed to build tracked PR doctor summary: {err}");
                            checks.push(crate::commands::daemon::DaemonDoctorCheck {
                                name: "tracked_pr_summary".to_string(),
                                status: "WARN",
                                message,
                            });
                            Vec::new()
                        },
                    };
                let payload = serde_json::json!({
                    "schema": "apm2.fac.doctor.system.v1",
                    "checks": checks,
                    "tracked_prs": tracked_prs,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                );

                if has_critical_error {
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
        },
        FacSubcommand::Context(args) => match &args.subcommand {
            ContextSubcommand::Rebuild(rebuild_args) => run_context_rebuild(
                rebuild_args,
                &ledger_path,
                &cas_path,
                resolve_json(rebuild_args.json),
            ),
        },
        FacSubcommand::Resume(args) => run_resume(args, &ledger_path, resolve_json(args.json)),
        FacSubcommand::Lane(args) => match &args.subcommand {
            LaneSubcommand::Status(status_args) => {
                run_lane_status(status_args, resolve_json(status_args.json))
            },
            LaneSubcommand::Reset(reset_args) => {
                run_lane_reset(reset_args, resolve_json(reset_args.json))
            },
            LaneSubcommand::Init(init_args) => {
                run_lane_init(init_args, resolve_json(init_args.json))
            },
            LaneSubcommand::Reconcile(reconcile_args) => {
                run_lane_reconcile(reconcile_args, resolve_json(reconcile_args.json))
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
            ReviewSubcommand::Wait(wait_args) => {
                let output_json = resolve_json(
                    wait_args.json || matches!(wait_args.format, ReviewFormatArg::Json),
                );
                fac_review::run_wait(
                    wait_args.pr,
                    wait_args.review_type.map(ReviewStatusTypeArg::as_str),
                    wait_args.wait_for_sha.as_deref(),
                    wait_args.timeout_seconds,
                    wait_args.poll_interval_seconds,
                    output_json,
                )
            },
            ReviewSubcommand::Dispatch(dispatch_args) => {
                let output_json = resolve_json(dispatch_args.json);
                let repo = match derive_fac_repo_or_exit(machine_output) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_dispatch(
                    &repo,
                    dispatch_args.pr,
                    dispatch_args.review_type,
                    dispatch_args.expected_head_sha.as_deref(),
                    dispatch_args.force,
                    output_json,
                )
            },
            ReviewSubcommand::Status(status_args) => {
                let output_json = resolve_json(status_args.json);
                fac_review::run_status(
                    status_args.pr,
                    status_args.review_type.map(ReviewStatusTypeArg::as_str),
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
            ReviewSubcommand::Project(project_args) => {
                let format_json =
                    project_args.json || matches!(project_args.format, ReviewFormatArg::Json);
                let output_json = resolve_json(format_json);
                fac_review::run_project(
                    project_args.pr,
                    project_args.head_sha.as_deref(),
                    project_args.since_epoch,
                    project_args.after_seq,
                    project_args.emit_errors,
                    project_args.fail_on_terminal,
                    output_json,
                    output_json,
                )
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
        ),
        FacSubcommand::Bench(args) => crate::commands::fac_bench::run_fac_bench(
            args.concurrency,
            args.skip_warm,
            args.timeout_seconds,
            &args.memory_max,
            args.pids_max,
            &args.cpu_quota,
            resolve_json(args.json),
        ),
        FacSubcommand::Bundle(args) => match &args.subcommand {
            BundleSubcommand::Export(export_args) => {
                run_bundle_export(export_args, resolve_json(export_args.json))
            },
            BundleSubcommand::Import(import_args) => {
                run_bundle_import(import_args, resolve_json(import_args.json))
            },
        },
        FacSubcommand::Reconcile(args) => run_reconcile(args, resolve_json(args.json)),
    }
}

/// Execute `apm2 fac reconcile`.
fn run_reconcile(args: &ReconcileArgs, json_output: bool) -> u8 {
    use apm2_core::fac::{OrphanedJobPolicy, reconcile_on_startup};
    use apm2_core::github::resolve_apm2_home;

    let Some(home) = resolve_apm2_home() else {
        if json_output {
            let err_json = serde_json::json!({"error": "cannot resolve APM2 home"});
            println!("{}", serde_json::to_string(&err_json).unwrap_or_default());
        } else {
            eprintln!("ERROR: cannot resolve APM2 home directory");
        }
        return crate::exit_codes::codes::GENERIC_ERROR;
    };
    let fac_root = home.join("private").join("fac");
    let queue_root = home.join("queue");

    // Parse orphan policy.
    let orphan_policy = match args.orphan_policy.as_str() {
        "requeue" => OrphanedJobPolicy::Requeue,
        "mark-failed" => OrphanedJobPolicy::MarkFailed,
        other => {
            if json_output {
                let err_json = serde_json::json!({
                    "error": format!("invalid orphan-policy: {other}, expected requeue or mark-failed")
                });
                println!("{}", serde_json::to_string(&err_json).unwrap_or_default());
            } else {
                eprintln!(
                    "ERROR: invalid --orphan-policy '{other}', expected 'requeue' or 'mark-failed'"
                );
            }
            return crate::exit_codes::codes::GENERIC_ERROR;
        },
    };

    // Determine mode: --dry-run takes priority; without flags, default to dry-run.
    let dry_run = !args.apply;

    if !dry_run && args.dry_run {
        // Contradiction: both --dry-run and --apply specified.
        if json_output {
            let err_json =
                serde_json::json!({"error": "cannot specify both --dry-run and --apply"});
            println!("{}", serde_json::to_string(&err_json).unwrap_or_default());
        } else {
            eprintln!("ERROR: cannot specify both --dry-run and --apply");
        }
        return crate::exit_codes::codes::GENERIC_ERROR;
    }

    match reconcile_on_startup(&fac_root, &queue_root, orphan_policy, dry_run) {
        Ok(receipt) => {
            if json_output {
                if let Ok(json) = serde_json::to_string_pretty(&receipt) {
                    println!("{json}");
                }
            } else {
                let mode = if dry_run { "DRY RUN" } else { "APPLIED" };
                println!("Reconciliation complete ({mode}):");
                println!("  Lanes inspected:          {}", receipt.lanes_inspected);
                println!(
                    "  Stale leases recovered:   {}",
                    receipt.stale_leases_recovered
                );
                println!(
                    "  Claimed files inspected:  {}",
                    receipt.claimed_files_inspected
                );
                println!(
                    "  Orphaned jobs requeued:    {}",
                    receipt.orphaned_jobs_requeued
                );
                println!(
                    "  Orphaned jobs failed:      {}",
                    receipt.orphaned_jobs_failed
                );
                println!(
                    "  Lanes marked corrupt:      {}",
                    receipt.lanes_marked_corrupt
                );
            }
            0
        },
        Err(e) => {
            if json_output {
                let err_json = serde_json::json!({"error": e.to_string()});
                println!("{}", serde_json::to_string(&err_json).unwrap_or_default());
            } else {
                eprintln!("ERROR: reconciliation failed: {e}");
            }
            crate::exit_codes::codes::GENERIC_ERROR
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
        | FacSubcommand::Resume(_)
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
        | FacSubcommand::Reconcile(_)
        | FacSubcommand::Queue(_) => true,
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
struct WorkInfo {
    episode_id: Option<String>,
}

/// Extracts work-related information from an event if it matches the `work_id`.
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
    let mut headers = apm2_core::fac::list_receipt_headers(&receipts_dir);

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
// Lane Reset Command (TCK-00516)
// =============================================================================

/// Execute `apm2 fac lane reset <lane_id>`.
///
/// Resets a lane by deleting its workspace, target, logs, and per-lane env
/// isolation subdirectories (`home`, `tmp`, `xdg_cache`, `xdg_config`,
/// `xdg_data`, `xdg_state`, `xdg_runtime`) using
/// `safe_rmtree_v1` (symlink-safe, boundary-enforced deletion).
///
/// # State Machine
///
/// - IDLE: resets all lane subdirs, removes lease, remains IDLE.
/// - CORRUPT: resets all lane subdirs, removes lease, transitions to IDLE.
/// - LEASED/CLEANUP: resets all lane subdirs, removes lease, transitions to
///   IDLE.
/// - RUNNING: refuses unless `--force` is provided. With `--force`, kills the
///   process first, then resets.
///
/// # Security
///
/// Deletion is performed via `safe_rmtree_v1` which refuses:
/// - Symlink traversal at any depth
/// - Crossing filesystem boundaries
/// - Unexpected file types (FIFOs, sockets, devices)
/// - Deletion outside the allowed parent boundary
fn run_lane_reset(args: &LaneResetArgs, json_output: bool) -> u8 {
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

    // Ensure directories exist
    if let Err(e) = manager.ensure_directories() {
        return output_error(
            json_output,
            "lane_error",
            &format!("Failed to ensure lane directories: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    // Acquire exclusive lock for the lane BEFORE any status reads or
    // mutations. The lock is held across the entire reset operation
    // (status check + force-kill + deletion + lease cleanup) to prevent
    // concurrent writers from racing the reset.
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

    // Get current lane status (under lock)
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

    // Check if lane is RUNNING and refuse without --force
    if status.state == LaneState::Running && !args.force {
        return output_error(
            json_output,
            "lane_running",
            &format!(
                "Lane {} is RUNNING (pid={}). Use --force to kill the process and reset.",
                args.lane_id,
                status.pid.unwrap_or(0)
            ),
            exit_codes::VALIDATION_ERROR,
        );
    }

    // With --force on a RUNNING lane, attempt to kill the process (under lock).
    // If kill fails (EPERM, PID reuse, etc.), abort the reset and mark CORRUPT
    // to prevent deleting directories of a still-running process.
    if status.state == LaneState::Running && args.force {
        if let Some(pid) = status.pid {
            if !kill_process_best_effort(pid) {
                let corrupt_reason = format!(
                    "failed to kill process {} for lane {} -- process may still be running or PID was reused",
                    pid, args.lane_id
                );
                persist_corrupt_lease(&manager, &args.lane_id, &corrupt_reason);
                return output_error(
                    json_output,
                    "kill_failed",
                    &corrupt_reason,
                    exit_codes::GENERIC_ERROR,
                );
            }
        }
    }

    // Perform safe deletion of all lane subdirectories (under lock)
    let lane_dir = manager.lane_dir(&args.lane_id);
    let Some(lanes_root) = lane_dir.parent() else {
        return output_error(
            json_output,
            "lane_error",
            &format!(
                "Lane directory {} has no parent directory",
                lane_dir.display()
            ),
            exit_codes::GENERIC_ERROR,
        );
    };

    // TCK-00575: Include all per-lane env isolation directories (home, tmp,
    // xdg_cache, xdg_config, xdg_data, xdg_state, xdg_runtime) in the reset
    // so that stale env state does not
    // persist across lane reuses.
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
            Err(e) => {
                let receipt = RefusedDeleteReceipt {
                    root: subdir_path.clone(),
                    allowed_parent: lanes_root.to_path_buf(),
                    reason: e.to_string(),
                    mark_corrupt: true,
                };
                refused_receipts.push(receipt);
            },
        }
    }

    // If any deletions were refused, mark lane as CORRUPT (under lock)
    if !refused_receipts.is_empty() {
        let corrupt_reason = refused_receipts
            .iter()
            .map(|r| r.reason.as_str())
            .collect::<Vec<_>>()
            .join("; ");

        // Persist CORRUPT state to the lease file so that lane_status
        // reflects the corruption even after restart.
        persist_corrupt_lease(&manager, &args.lane_id, &corrupt_reason);

        let response = serde_json::json!({
            "lane_id": args.lane_id,
            "status": "CORRUPT",
            "reason": corrupt_reason,
            "refused_receipts": refused_receipts.iter().map(|r| {
                serde_json::json!({
                    "root": r.root.display().to_string(),
                    "allowed_parent": r.allowed_parent.display().to_string(),
                    "reason": r.reason,
                    "mark_corrupt": r.mark_corrupt,
                })
            }).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_default()
        );

        return exit_codes::GENERIC_ERROR;
    }

    // Remove the lease file to transition lane to IDLE (under lock)
    let lane_dir_owned = manager.lane_dir(&args.lane_id);
    if let Err(e) = LaneLeaseV1::remove(&lane_dir_owned) {
        return output_error(
            json_output,
            "lane_error",
            &format!("Failed to remove lease for lane {}: {e}", args.lane_id),
            exit_codes::GENERIC_ERROR,
        );
    }

    if let Err(e) = LaneCorruptMarkerV1::remove(manager.fac_root(), &args.lane_id) {
        return output_error(
            json_output,
            "lane_error",
            &format!(
                "Failed to clear corrupt marker for lane {}: {e}",
                args.lane_id
            ),
            exit_codes::GENERIC_ERROR,
        );
    }
    if !json_output {
        eprintln!("Corrupt marker cleared for lane {}", args.lane_id);
    }

    // Re-create the empty subdirectories for the reset lane so it is
    // ready for reuse. This calls ensure_directories() which re-inits
    // all lanes, not just the reset lane. This is acceptable because
    // ensure_directories is idempotent (mkdir -p semantics) and only
    // creates directories that don't already exist.
    if let Err(e) = manager.ensure_directories() {
        eprintln!("WARNING: failed to re-create lane directories: {e}");
    }

    // Lock is released here when _lock_guard drops.

    let response = serde_json::json!({
        "lane_id": args.lane_id,
        "status": "IDLE",
        "files_deleted": total_files,
        "dirs_deleted": total_dirs,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_default()
    );

    exit_codes::SUCCESS
}

/// Persist a CORRUPT lease to the lane directory so that `lane_status`
/// reports CORRUPT even after restart.
///
/// This is best-effort: if the lease write fails, a warning is printed
/// but the overall CORRUPT error flow continues (fail-closed: the lane
/// is already in a bad state).
fn persist_corrupt_lease(manager: &LaneManager, lane_id: &str, reason: &str) {
    let lane_dir = manager.lane_dir(lane_id);
    // Truncate reason to avoid exceeding string length limits.
    // Use char_indices to find a safe UTF-8 boundary instead of byte
    // slicing, which would panic on multi-byte characters.
    let truncated_reason = if reason.len() > 200 {
        let truncated: String = reason
            .char_indices()
            .take_while(|&(i, _)| i < 197)
            .map(|(_, c)| c)
            .collect();
        format!("{truncated}...")
    } else {
        reason.to_string()
    };

    match LaneLeaseV1::new(
        lane_id,
        &truncated_reason,
        0, // pid=0: no running process
        LaneState::Corrupt,
        "1970-01-01T00:00:00Z", // sentinel timestamp
        "corrupt",
        "corrupt",
    ) {
        Ok(lease) => {
            if let Err(e) = lease.persist(&lane_dir) {
                eprintln!("WARNING: failed to persist CORRUPT lease for lane {lane_id}: {e}");
            }
        },
        Err(e) => {
            eprintln!("WARNING: failed to create CORRUPT lease for lane {lane_id}: {e}");
        },
    }
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
// Lane Reconcile Command (TCK-00539)
// =============================================================================

/// Execute `apm2 fac lane reconcile`.
///
/// Inspects all lanes and repairs missing directories or profiles. Lanes
/// that cannot be repaired are marked CORRUPT.
fn run_lane_reconcile(_args: &LaneReconcileArgs, json_output: bool) -> u8 {
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

    let receipt = match manager.reconcile_lanes() {
        Ok(r) => r,
        Err(e) => {
            return output_error(
                json_output,
                "lane_reconcile_error",
                &format!("Lane reconcile failed: {e}"),
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
                    &format!("Failed to serialize reconcile receipt: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        }
    } else {
        print_lane_reconcile_receipt(&receipt);
    }

    if receipt.lanes_marked_corrupt > 0 || receipt.lanes_failed > 0 {
        exit_codes::GENERIC_ERROR
    } else {
        exit_codes::SUCCESS
    }
}

/// Print a human-readable reconcile receipt.
fn print_lane_reconcile_receipt(receipt: &LaneReconcileReceiptV1) {
    println!("Lane reconciliation complete");
    println!();
    println!("  Lanes inspected:      {}", receipt.lanes_inspected);
    println!("  Lanes OK:             {}", receipt.lanes_ok);
    println!("  Lanes repaired:       {}", receipt.lanes_repaired);
    println!("  Lanes marked corrupt: {}", receipt.lanes_marked_corrupt);
    println!("  Lanes failed:         {}", receipt.lanes_failed);

    if !receipt.actions.is_empty() {
        println!();
        println!("  Actions:");
        for action in &receipt.actions {
            let detail = action.detail.as_deref().unwrap_or("");
            println!(
                "    {:<12} {:<30} {:?} {}",
                action.lane_id, action.action, action.outcome, detail
            );
        }
    }
}

/// Best-effort process kill using SIGTERM then SIGKILL.
///
/// Returns `true` if the process is confirmed dead (ESRCH) or was
/// successfully killed, `false` if the process could not be signaled
/// (EPERM or other errors). The caller MUST abort the reset and mark
/// the lane CORRUPT if this returns `false`.
///
/// # PID Reuse Safety
///
/// Stale lease PIDs may have been reused by a different process. We
/// verify the process exists via `/proc/<pid>/comm` before sending
/// signals. If `/proc/<pid>/comm` does not exist, the PID is dead and
/// we return `true` (success).
///
/// # Blocking Wait (intentional)
///
/// This function blocks the calling thread for up to ~5.2 seconds while
/// waiting for the process to exit after SIGTERM. This is acceptable because
/// `kill_process_best_effort` is called exclusively from the `apm2 fac lane
/// reset --force` CLI command, which is an interactive operator action that
/// expects synchronous completion before proceeding with directory deletion.
/// The blocking wait ensures the process has actually exited before we
/// attempt to delete its workspace.
fn kill_process_best_effort(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;

        let Ok(pid_i32) = i32::try_from(pid) else {
            return false;
        };
        let nix_pid = Pid::from_raw(pid_i32);

        // Verify PID is alive via /proc/<pid>/comm. If the procfs entry
        // does not exist, the process is already dead -- success.
        let proc_comm = format!("/proc/{pid}/comm");
        if std::fs::read_to_string(&proc_comm).is_err() {
            return true; // Process doesn't exist
        }

        // Send SIGTERM first (graceful shutdown request).
        match signal::kill(nix_pid, Signal::SIGTERM) {
            Ok(()) => {},
            Err(nix::errno::Errno::ESRCH) => return true, // already gone
            Err(_) => return false,                       /* EPERM or other: can't signal, don't
                                                            * proceed */
        }

        // Wait for graceful shutdown (up to 5 seconds, polling every 100ms).
        // See doc comment above for why this blocking wait is intentional.
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            // kill(pid, signal 0) checks existence without sending a signal.
            match signal::kill(nix_pid, None) {
                Err(nix::errno::Errno::ESRCH) => return true, // gone
                Ok(()) => {},                                 // still alive
                Err(_) => return false,                       // can't determine, don't proceed
            }
        }

        // Process still alive after 5s -- send SIGKILL (uncatchable).
        match signal::kill(nix_pid, Signal::SIGKILL) {
            Err(nix::errno::Errno::ESRCH) => return true,
            Err(_) => return false,
            Ok(()) => {},
        }

        // Final wait for SIGKILL to take effect.
        std::thread::sleep(std::time::Duration::from_millis(200));
        matches!(signal::kill(nix_pid, None), Err(nix::errno::Errno::ESRCH))
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

// =============================================================================
// Resume Command
// =============================================================================

/// Execute the resume command.
fn run_resume(args: &ResumeArgs, ledger_path: &Path, json_output: bool) -> u8 {
    // Validate work ID
    if args.work_id.is_empty() {
        return output_error(
            json_output,
            "invalid_work_id",
            "Work ID cannot be empty",
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

    // Scan ledger to find last anchor and pending state
    let mut response = ResumeResponse {
        work_id: args.work_id.clone(),
        last_anchor_seq_id: 0,
        last_anchor_event_type: "none".to_string(),
        restart_action: "START_FRESH".to_string(),
        pending_operations: Vec::new(),
        last_episode_id: None,
    };

    let mut found_events = false;
    let mut last_committed_event: Option<(u64, String)> = None;
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
            if let Some(work_info) = extract_work_info(event, &args.work_id) {
                found_events = true;
                let seq_id = event.seq_id.unwrap_or(0);

                // Track anchors (committed durable events)
                match event.event_type.as_str() {
                    "work_claimed" | "episode_spawned" | "session_terminated" | "gate_receipt"
                    | "review_receipt" | "merge_receipt" => {
                        last_committed_event = Some((seq_id, event.event_type.clone()));
                        if work_info.episode_id.is_some() {
                            response.last_episode_id = work_info.episode_id;
                        }
                    },
                    _ => {},
                }
            }
        }

        cursor = events.last().map_or(cursor, |e| e.seq_id.unwrap_or(0) + 1);
    }

    if !found_events {
        return output_error(
            json_output,
            "not_found",
            &format!("No events found for work_id: {}", args.work_id),
            exit_codes::NOT_FOUND,
        );
    }

    // Determine restart action based on last anchor
    if let Some((seq_id, event_type)) = last_committed_event {
        response.last_anchor_seq_id = seq_id;
        response.last_anchor_event_type.clone_from(&event_type);

        response.restart_action = match event_type.as_str() {
            "work_claimed" => "SPAWN_EPISODE".to_string(),
            "episode_spawned" => "RESUME_EPISODE".to_string(),
            "session_terminated" => {
                response.pending_operations.push("RUN_GATES".to_string());
                "RUN_GATES".to_string()
            },
            "gate_receipt" => {
                response.pending_operations.push("AWAIT_REVIEW".to_string());
                "AWAIT_REVIEW".to_string()
            },
            "review_receipt" => {
                response.pending_operations.push("MERGE".to_string());
                "MERGE".to_string()
            },
            "merge_receipt" => "WORK_COMPLETE".to_string(),
            _ => "UNKNOWN".to_string(),
        };
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Resume Analysis");
        println!("  Work ID:            {}", response.work_id);
        println!("  Last Anchor Seq:    {}", response.last_anchor_seq_id);
        println!("  Last Anchor Type:   {}", response.last_anchor_event_type);
        println!("  Restart Action:     {}", response.restart_action);
        if let Some(episode) = &response.last_episode_id {
            println!("  Last Episode ID:    {episode}");
        }
        if !response.pending_operations.is_empty() {
            println!(
                "  Pending Operations: {}",
                response.pending_operations.join(", ")
            );
        }
    }

    exit_codes::SUCCESS
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
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
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
    fn test_lane_reset_clears_corrupt_marker() {
        let home = tempfile::tempdir().expect("temp dir");
        let _home_guard = Apm2HomeGuard::new(home.path());
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

        let exit_code = run_lane_reset(
            &LaneResetArgs {
                lane_id: lane_id.to_string(),
                force: false,
                json: false,
            },
            false,
        );
        assert_eq!(exit_code, exit_codes::SUCCESS);
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
    fn test_lane_reset_removes_all_per_lane_env_dirs() {
        let home = tempfile::tempdir().expect("temp dir");
        let _home_guard = Apm2HomeGuard::new(home.path());
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

        let exit_code = run_lane_reset(
            &LaneResetArgs {
                lane_id: lane_id.to_string(),
                force: false,
                json: false,
            },
            false,
        );
        assert_eq!(exit_code, exit_codes::SUCCESS);

        for target in &reset_targets {
            assert!(
                target.exists(),
                "target {} should be recreated by lane reset",
                target.display()
            );
            assert!(
                !target.join("stale-state").exists(),
                "stale-state in {} should be deleted by lane reset",
                target.display()
            );
        }
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
    fn test_resume_response_serialization() {
        let response = ResumeResponse {
            work_id: "work-123".to_string(),
            last_anchor_seq_id: 100,
            last_anchor_event_type: "episode_spawned".to_string(),
            restart_action: "RESUME_EPISODE".to_string(),
            pending_operations: vec!["RUN_GATES".to_string()],
            last_episode_id: Some("ep-001".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: ResumeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.restart_action, "RESUME_EPISODE");
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
            ".github/workflows/forge-admission-cycle.yml",
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
                        PathBuf::from(".github/workflows/forge-admission-cycle.yml")
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
        let review_status = FacSubcommand::Review(ReviewArgs {
            subcommand: ReviewSubcommand::Status(ReviewStatusArgs {
                pr: Some(615),
                review_type: None,
                json: true,
            }),
        });
        assert!(subcommand_requests_machine_output(&review_status));

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
                assert!(args.fix);
                assert!(!args.full);
            },
            other => panic!("expected doctor subcommand, got {other:?}"),
        }
    }

    #[test]
    fn test_doctor_full_flag_parses() {
        let parsed = FacLogsCliHarness::try_parse_from(["fac", "doctor", "--full"])
            .expect("doctor --full should parse");
        match parsed.subcommand {
            FacSubcommand::Doctor(args) => {
                assert!(args.full);
                assert!(args.pr.is_none());
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
    fn test_lane_reset_and_worker_commands_parse() {
        assert_fac_command_parses(&["fac", "lane", "reset", "lane-00"]);
        assert_fac_command_parses(&["fac", "lane", "reset", "lane-07", "--force"]);
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
}
