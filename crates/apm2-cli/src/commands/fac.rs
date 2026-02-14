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
//! - `apm2 fac review comment` - Publish one SHA-bound finding comment
//! - `apm2 fac review verdict` - Show/set SHA-bound approve/deny verdicts per
//!   review dimension
//! - `apm2 fac services status` - Inspect daemon/worker managed service health
//! - `apm2 fac restart --pr <PR_NUMBER>` - Intelligent pipeline restart from
//!   optimal point
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
    LaneLeaseV1, LaneManager, LaneState, LaneStatusV1, PROJECTION_ARTIFACT_SCHEMA_IDENTIFIER,
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
use crate::commands::role_launch::{self, RoleLaunchArgs};
use crate::commands::{fac_pr, fac_review};
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
const SERVICE_STATUS_PROPERTIES: [&str; 6] = [
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "MainPID",
    "ActiveEnterTimestampMonotonic",
];

// =============================================================================
// Command Types
// =============================================================================

/// FAC command group.
#[derive(Debug, Args)]
pub struct FacCommand {
    /// Output format (text or json).
    #[arg(long, default_value = "false")]
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

    /// Show receipt from CAS.
    ///
    /// Retrieves and displays a receipt artifact from content-addressed storage
    /// by its hash. Supports gate receipts, review receipts, and summary
    /// receipts.
    Receipt(ReceiptArgs),

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

    /// GitHub App credential management and PR operations.
    ///
    /// Provides `auth-setup` for bootstrapping credentials and
    /// `auth-check` for verifying they are accessible.
    Pr(fac_pr::PrArgs),
}

/// Arguments for `apm2 fac gates`.
#[derive(Debug, Args)]
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

    /// CPU quota for bounded test execution.
    #[arg(long, default_value = "200%")]
    pub cpu_quota: String,
}

/// Arguments for `apm2 fac work`.
#[derive(Debug, Args)]
pub struct WorkArgs {
    #[command(subcommand)]
    pub subcommand: WorkSubcommand,
}

/// Arguments for `apm2 fac doctor`.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Output in JSON format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
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
}

/// Arguments for `apm2 fac work list`.
#[derive(Debug, Args)]
pub struct WorkListArgs {
    /// Return only claimable work items.
    #[arg(long, default_value_t = false)]
    pub claimable_only: bool,
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
}

/// Arguments for `apm2 fac receipt`.
#[derive(Debug, Args)]
pub struct ReceiptArgs {
    #[command(subcommand)]
    pub subcommand: ReceiptSubcommand,
}

/// Receipt subcommands.
#[derive(Debug, Subcommand)]
pub enum ReceiptSubcommand {
    /// Show receipt from CAS.
    Show(ReceiptShowArgs),
}

/// Arguments for `apm2 fac receipt show`.
#[derive(Debug, Args)]
pub struct ReceiptShowArgs {
    /// Receipt hash (hex-encoded BLAKE3).
    pub receipt_hash: String,
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
}

/// Arguments for `apm2 fac resume`.
#[derive(Debug, Args)]
pub struct ResumeArgs {
    /// Work identifier to analyze for resume point.
    pub work_id: String,

    /// Maximum number of events to scan from the end of the ledger.
    #[arg(long, default_value_t = DEFAULT_SCAN_LIMIT)]
    pub limit: u64,
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
}

/// Arguments for `apm2 fac lane status`.
#[derive(Debug, Args)]
pub struct LaneStatusArgs {
    /// Show only lanes matching this state (IDLE, RUNNING, LEASED, CLEANUP,
    /// CORRUPT).
    #[arg(long)]
    pub state: Option<String>,
}

/// Arguments for `apm2 fac lane reset`.
#[derive(Debug, Args)]
pub struct LaneResetArgs {
    /// Lane identifier to reset (e.g., `lane-00`).
    pub lane_id: String,

    /// Force reset even if lane is RUNNING. Kills the lane's process first.
    #[arg(long, default_value_t = false)]
    pub force: bool,
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

    /// Selector token to resolve (typed by `--selector-type`).
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
    /// Materialize local review inputs (diff + commit history) under /tmp.
    Prepare(ReviewPrepareArgs),
    /// Publish review findings and auto-generate machine-readable metadata.
    Publish(ReviewPublishArgs),
    /// Retrieve structured review findings for a PR head SHA.
    Findings(ReviewFindingsArgs),
    /// Publish one SHA-bound finding comment with machine-readable metadata.
    Comment(ReviewCommentArgs),
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

    /// Ignore local cached comments and re-fetch from GitHub projection.
    #[arg(long, default_value_t = false)]
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

/// Arguments for `apm2 fac review publish`.
#[derive(Debug, Args)]
pub struct ReviewPublishArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Optional head SHA override (defaults to PR head SHA).
    #[arg(long)]
    pub sha: Option<String>,

    /// Review dimension to publish (`security` or `code-quality`).
    #[arg(long = "type", value_enum)]
    pub review_type: fac_review::ReviewPublishTypeArg,

    /// Path to markdown findings body.
    #[arg(long)]
    pub body_file: PathBuf,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac review comment`.
#[derive(Debug, Args)]
pub struct ReviewCommentArgs {
    /// Pull request number.
    #[arg(long)]
    pub pr: Option<u32>,

    /// Optional head SHA override (defaults to `git rev-parse HEAD`).
    #[arg(long)]
    pub sha: Option<String>,

    /// Finding severity (`blocker`, `major`, `minor`, or `nit`).
    #[arg(long, value_enum)]
    pub severity: fac_review::ReviewCommentSeverityArg,

    /// Finding type (`security` or `code-quality`).
    #[arg(long = "type", value_enum)]
    pub review_type: fac_review::ReviewCommentTypeArg,

    /// Finding body text. If omitted, body is read from stdin.
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

    /// Keep prepared review input files under /tmp after verdict is written.
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
    /// Error code.
    pub code: String,
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
    /// Error encountered while checking the unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServicesStatusResponse {
    /// List of managed services.
    pub services: Vec<ServiceStatusResponse>,
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

fn run_services_status(json_output: bool) -> u8 {
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
                    error: Some(message),
                }
            },
        };

        let healthy = status.error.is_none()
            && status.load_state == "loaded"
            && status.active_state == "active"
            && status.enabled == "enabled";
        if !healthy {
            degraded = true;
        }

        if json_output {
            services.push(status.clone());
        } else {
            print_services_status_line(&status, healthy);
            services.push(status);
        }
    }

    if json_output {
        let response = ServicesStatusResponse {
            services: services.clone(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&response) {
            println!("{json}");
        } else {
            println!("{{\"services\":[]}}");
            degraded = true;
        }
    } else if services.is_empty() {
        println!("No managed FAC services configured");
        degraded = true;
    } else {
        println!();
        println!(
            "Summary: {}/{} service entries healthy",
            services
                .iter()
                .filter(|svc| {
                    svc.error.is_none()
                        && svc.load_state == "loaded"
                        && svc.active_state == "active"
                        && svc.enabled == "enabled"
                })
                .count(),
            services.len()
        );
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

    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "LoadState" => load_state = value.to_string(),
                "ActiveState" => active_state = value.to_string(),
                "SubState" => sub_state = value.to_string(),
                "UnitFileState" => enabled = value.to_string(),
                "MainPID" => main_pid = value.to_string(),
                "ActiveEnterTimestampMonotonic" => active_enter_timestamp = value.to_string(),
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

    Ok(ServiceStatusResponse {
        unit: unit_name.to_string(),
        scope: scope.label().to_string(),
        load_state,
        active_state,
        sub_state,
        enabled,
        main_pid,
        uptime_seconds,
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

fn print_services_status_line(status: &ServiceStatusResponse, healthy: bool) {
    if let Some(error) = status.error.as_deref() {
        println!("● {}/{}: degraded", status.unit, status.scope);
        println!("  error:      {error}");
        return;
    }

    let health_status = if healthy { "healthy" } else { "degraded" };
    println!("● {} ({}) {}", status.unit, status.scope, health_status);
    println!("  LoadState:  {}", status.load_state);
    println!("  ActiveState:{}", status.active_state);
    println!("  SubState:   {}", status.sub_state);
    println!("  Enabled:    {}", status.enabled);
    println!("  PID:        {}", status.main_pid);
    println!("  Uptime:     {}s", status.uptime_seconds);
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
    let json_output = cmd.json;

    // TCK-00536: Validate FAC root permissions on every FAC command entry.
    // Refuse to proceed if `$APM2_HOME` or `$APM2_HOME/private/fac` have
    // unsafe permissions (group/world-writable or wrong ownership).
    if let Err(err) = crate::commands::fac_permissions::validate_fac_root_permissions() {
        eprintln!("ERROR: FAC root permissions check failed (fail-closed).");
        eprintln!("{err}");
        return exit_codes::GENERIC_ERROR;
    }

    let ledger_path = resolve_ledger_path(cmd.ledger_path.as_deref());
    let cas_path = resolve_cas_path(cmd.cas_path.as_deref());

    if !matches!(
        cmd.subcommand,
        FacSubcommand::Gates(_)
            | FacSubcommand::Doctor(_)
            | FacSubcommand::Lane(_)
            | FacSubcommand::Services(_)
            | FacSubcommand::Worker(_)
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
            json_output,
        ),
        FacSubcommand::Work(args) => match &args.subcommand {
            WorkSubcommand::Status(status_args) => {
                run_work_status(status_args, operator_socket, json_output)
            },
            WorkSubcommand::List(list_args) => {
                run_work_list(list_args, operator_socket, json_output)
            },
        },
        FacSubcommand::Doctor(args) => {
            match crate::commands::daemon::doctor(
                operator_socket,
                config_path,
                json_output || args.json,
            ) {
                Ok(()) => exit_codes::SUCCESS,
                Err(_) => exit_codes::GENERIC_ERROR,
            }
        },
        FacSubcommand::Services(args) => match &args.subcommand {
            ServicesSubcommand::Status(status_args) => {
                run_services_status(json_output || status_args.json)
            },
        },
        FacSubcommand::RoleLaunch(args) => {
            match role_launch::handle_role_launch(
                args,
                &ledger_path,
                &cas_path,
                session_socket,
                json_output,
            ) {
                Ok(()) => exit_codes::SUCCESS,
                Err(error) => error
                    .downcast_ref::<role_launch::RoleLaunchError>()
                    .map_or_else(
                        || {
                            output_error(
                                json_output,
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
            EpisodeSubcommand::Inspect(inspect_args) => {
                run_episode_inspect(inspect_args, &ledger_path, &cas_path, json_output)
            },
        },
        FacSubcommand::Receipt(args) => match &args.subcommand {
            ReceiptSubcommand::Show(show_args) => {
                run_receipt_show(show_args, &cas_path, json_output)
            },
        },
        FacSubcommand::Context(args) => match &args.subcommand {
            ContextSubcommand::Rebuild(rebuild_args) => {
                run_context_rebuild(rebuild_args, &ledger_path, &cas_path, json_output)
            },
        },
        FacSubcommand::Resume(args) => run_resume(args, &ledger_path, json_output),
        FacSubcommand::Lane(args) => match &args.subcommand {
            LaneSubcommand::Status(status_args) => run_lane_status(status_args, json_output),
            LaneSubcommand::Reset(reset_args) => run_lane_reset(reset_args, json_output),
        },
        FacSubcommand::Push(args) => {
            let repo = match derive_fac_repo_or_exit(json_output) {
                Ok(value) => value,
                Err(code) => return code,
            };
            fac_review::run_push(
                &repo,
                &args.remote,
                args.branch.as_deref(),
                args.ticket.as_deref(),
            )
        },
        FacSubcommand::Restart(args) => {
            let repo = match derive_fac_repo_or_exit(json_output) {
                Ok(value) => value,
                Err(code) => return code,
            };
            fac_review::run_restart(&repo, args.pr, args.force, json_output)
        },
        FacSubcommand::Logs(args) => {
            let repo = match derive_fac_repo_or_exit(json_output || args.json) {
                Ok(value) => value,
                Err(code) => return code,
            };
            fac_review::run_logs(
                args.pr,
                &repo,
                args.selector_type.as_deref(),
                args.selector.as_deref(),
                json_output || args.json,
            )
        },
        FacSubcommand::Pipeline(args) => {
            let repo = match derive_fac_repo_or_exit(json_output) {
                Ok(value) => value,
                Err(code) => return code,
            };
            fac_review::run_pipeline(&repo, args.pr, &args.sha)
        },
        FacSubcommand::Review(args) => match &args.subcommand {
            ReviewSubcommand::Run(run_args) => {
                let repo = match derive_fac_repo_or_exit(json_output) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_review(
                    &repo,
                    run_args.pr,
                    run_args.review_type,
                    run_args.expected_head_sha.as_deref(),
                    run_args.force,
                    json_output,
                )
            },
            ReviewSubcommand::Wait(wait_args) => fac_review::run_wait(
                wait_args.pr,
                wait_args.review_type.map(ReviewStatusTypeArg::as_str),
                wait_args.wait_for_sha.as_deref(),
                wait_args.timeout_seconds,
                wait_args.poll_interval_seconds,
                matches!(wait_args.format, ReviewFormatArg::Json),
            ),
            ReviewSubcommand::Dispatch(dispatch_args) => {
                let repo = match derive_fac_repo_or_exit(json_output) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_dispatch(
                    &repo,
                    dispatch_args.pr,
                    dispatch_args.review_type,
                    dispatch_args.expected_head_sha.as_deref(),
                    dispatch_args.force,
                    json_output,
                )
            },
            ReviewSubcommand::Status(status_args) => fac_review::run_status(
                status_args.pr,
                status_args.review_type.map(ReviewStatusTypeArg::as_str),
                json_output || status_args.json,
            ),
            ReviewSubcommand::Prepare(prepare_args) => {
                let repo = match derive_fac_repo_or_exit(json_output || prepare_args.json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_prepare(
                    &repo,
                    prepare_args.pr,
                    prepare_args.sha.as_deref(),
                    json_output || prepare_args.json,
                )
            },
            ReviewSubcommand::Publish(publish_args) => {
                let repo = match derive_fac_repo_or_exit(json_output || publish_args.json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_publish(
                    &repo,
                    publish_args.pr,
                    publish_args.sha.as_deref(),
                    publish_args.review_type,
                    &publish_args.body_file,
                    json_output || publish_args.json,
                )
            },
            ReviewSubcommand::Findings(findings_args) => {
                let repo = match derive_fac_repo_or_exit(json_output || findings_args.json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_findings(
                    &repo,
                    findings_args.pr,
                    findings_args.sha.as_deref(),
                    findings_args.refresh,
                    json_output || findings_args.json,
                )
            },
            ReviewSubcommand::Comment(comment_args) => {
                let repo = match derive_fac_repo_or_exit(json_output || comment_args.json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_comment(
                    &repo,
                    comment_args.pr,
                    comment_args.sha.as_deref(),
                    comment_args.severity,
                    comment_args.review_type,
                    comment_args.body.as_deref(),
                    json_output || comment_args.json,
                )
            },
            ReviewSubcommand::Verdict(verdict_args) => match &verdict_args.subcommand {
                ReviewVerdictSubcommand::Show(show_args) => {
                    let repo = match derive_fac_repo_or_exit(json_output || show_args.json) {
                        Ok(value) => value,
                        Err(code) => return code,
                    };
                    fac_review::run_verdict_show(
                        &repo,
                        show_args.pr,
                        show_args.sha.as_deref(),
                        json_output || show_args.json,
                    )
                },
                ReviewVerdictSubcommand::Set(set_args) => {
                    let repo = match derive_fac_repo_or_exit(json_output || set_args.json) {
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
                        set_args.keep_prepared_inputs,
                        json_output || set_args.json,
                    )
                },
            },
            ReviewSubcommand::Project(project_args) => fac_review::run_project(
                project_args.pr,
                project_args.head_sha.as_deref(),
                project_args.since_epoch,
                project_args.after_seq,
                project_args.emit_errors,
                project_args.fail_on_terminal,
                matches!(project_args.format, ReviewFormatArg::Json),
                json_output,
            ),
            ReviewSubcommand::Tail(tail_args) => {
                fac_review::run_tail(tail_args.lines, tail_args.follow)
            },
            ReviewSubcommand::Terminate(term_args) => {
                let repo = match derive_fac_repo_or_exit(json_output || term_args.json) {
                    Ok(value) => value,
                    Err(code) => return code,
                };
                fac_review::run_terminate(
                    &repo,
                    term_args.pr,
                    term_args.review_type.as_str(),
                    json_output || term_args.json,
                )
            },
        },
        FacSubcommand::Worker(args) => crate::commands::fac_worker::run_fac_worker(
            args.once,
            args.poll_interval_secs,
            args.max_jobs,
            json_output,
        ),
        FacSubcommand::Pr(args) => fac_pr::run_pr(args, json_output),
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

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Work Status");
                println!("  Work ID:            {}", response.work_id);
                println!("  Status:             {}", response.status);
                if let Some(actor) = &response.actor_id {
                    println!("  Actor ID:           {actor}");
                }
                if let Some(role) = &response.role {
                    println!("  Role:               {role}");
                }
                if let Some(session_id) = &response.latest_episode_id {
                    println!("  Session ID:         {session_id}");
                }
                if let Some(lease_id) = &response.latest_receipt_hash {
                    println!("  Lease ID:           {lease_id}");
                }
            }

            exit_codes::SUCCESS
        },
        Err(error) => handle_protocol_error(json_output, &error),
    }
}

/// Execute the work list command.
fn run_work_list(args: &WorkListArgs, operator_socket: &Path, json_output: bool) -> u8 {
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

            if json_output {
                #[derive(Debug, Serialize)]
                struct WorkListJson<'a> {
                    claimable_only: bool,
                    total: usize,
                    items: &'a [WorkStatusResponse],
                }

                let output = WorkListJson {
                    claimable_only: args.claimable_only,
                    total: rows.len(),
                    items: &rows,
                };

                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Work List");
                println!("  Claimable Only: {}", args.claimable_only);
                println!("  Total:          {}", rows.len());
                for row in &rows {
                    println!("  - {} [{}]", row.work_id, row.status);
                }
            }

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
                .and_then(|s| hex::decode(s).ok()),
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
            .and_then(|s| hex::decode(s).ok()),
    })
}

/// Loads a tool log index from CAS by hash.
fn load_tool_log_index_from_cas(cas_path: &Path, hash: &[u8]) -> Option<ToolLogIndexV1> {
    let Ok(file_path) = resolve_cas_file_path(cas_path, hash, "tool_log_index_hash") else {
        return None;
    };

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

#[derive(Debug)]
enum CasHashParseError {
    Empty {
        field: &'static str,
    },
    InvalidHex {
        field: &'static str,
        error: hex::FromHexError,
    },
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl std::fmt::Display for CasHashParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty { field } => write!(f, "{field} is empty"),
            Self::InvalidHex { field, error } => write!(f, "{field} is not valid hex: {error}"),
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => {
                write!(f, "{field} must be {expected} bytes, got {actual} bytes")
            },
        }
    }
}

fn parse_cas_hash_32(field: &'static str, value: &str) -> Result<[u8; 32], CasHashParseError> {
    if value.is_empty() {
        return Err(CasHashParseError::Empty { field });
    }
    let bytes =
        hex::decode(value).map_err(|error| CasHashParseError::InvalidHex { field, error })?;
    if bytes.len() != 32 {
        return Err(CasHashParseError::InvalidLength {
            field,
            expected: 32,
            actual: bytes.len(),
        });
    }
    let mut parsed = [0u8; 32];
    parsed.copy_from_slice(&bytes);
    Ok(parsed)
}

fn output_hash_validation_error(json_output: bool, field: &str, error: &CasHashParseError) -> u8 {
    output_error(
        json_output,
        "invalid_hash",
        &format!("invalid {field}: {error}"),
        exit_codes::VALIDATION_ERROR,
    )
}

fn resolve_cas_file_path(
    cas_path: &Path,
    hash: &[u8],
    field: &'static str,
) -> Result<PathBuf, CasHashParseError> {
    if hash.len() != 32 {
        return Err(CasHashParseError::InvalidLength {
            field,
            expected: 32,
            actual: hash.len(),
        });
    }
    let hex_hash = hex::encode(hash);
    let (prefix, suffix) = hex_hash.split_at(4);
    Ok(cas_path.join("objects").join(prefix).join(suffix))
}

fn parse_cas_hash_to_path(
    cas_path: &Path,
    value: &str,
    field: &'static str,
) -> Result<(PathBuf, [u8; 32]), CasHashParseError> {
    let hash = parse_cas_hash_32(field, value)?;
    Ok((resolve_cas_file_path(cas_path, &hash, field)?, hash))
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

    let (file_path, hash_bytes) =
        match parse_cas_hash_to_path(cas_path, &args.receipt_hash, "receipt_hash") {
            Ok(value) => value,
            Err(error) => {
                return output_hash_validation_error(json_output, "receipt hash", &error);
            },
        };

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
        hash: args.receipt_hash.clone(),
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
    let output_dir = if let Some(output_dir) = &args.output_dir {
        output_dir.clone()
    } else {
        let apm2_home = match crate::commands::fac_review::apm2_home_dir() {
            Ok(apm2_home) => apm2_home,
            Err(e) => {
                return output_error(
                    json_output,
                    "home_dir_error",
                    &format!("failed to resolve APM2 home directory: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };
        apm2_home
            .join("private")
            .join("fac")
            .join("context_rebuild")
            .join(&args.episode_id)
    };

    // Create output directory
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
    let mut context_pack_hash: Option<[u8; 32]> = None;
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
                            if let Some(hash_str) =
                                payload.get("context_pack_hash").and_then(|v| v.as_str())
                            {
                                let parsed_hash = match parse_cas_hash_32(
                                    "context_pack_hash",
                                    hash_str,
                                ) {
                                    Ok(hash) => hash,
                                    Err(error) => {
                                        return output_error(
                                            json_output,
                                            "invalid_hash",
                                            &format!(
                                                "Invalid context pack hash in episode event: {error}"
                                            ),
                                            exit_codes::VALIDATION_ERROR,
                                        );
                                    },
                                };
                                context_pack_hash = Some(parsed_hash);
                            }
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
    let hex_hash = hex::encode(context_pack_hash);
    let (pack_path, _) = match parse_cas_hash_to_path(cas_path, &hex_hash, "context pack hash") {
        Ok(value) => value,
        Err(error) => {
            return output_error(
                json_output,
                "invalid_hash",
                &format!("Invalid context pack hash in ledger: {error}"),
                exit_codes::VALIDATION_ERROR,
            );
        },
    };

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
                    let artifact_hash = match parse_cas_hash_32("artifact hash", hash_str) {
                        Ok(value) => value,
                        Err(error) => {
                            return output_error(
                                json_output,
                                "invalid_hash",
                                &format!("Invalid artifact hash in context pack: {error}"),
                                exit_codes::VALIDATION_ERROR,
                            );
                        },
                    };
                    if retrieve_artifact_to_dir(cas_path, &artifact_hash, &output_dir).is_ok() {
                        artifacts_retrieved += 1;
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

    if json_output {
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
    } else {
        // Human-readable table output
        println!("{:<12} {:<10} {:<32} STARTED", "LANE", "STATE", "JOB");
        println!("{}", "-".repeat(72));
        for status in &filtered {
            println!("{status}");
        }
        println!();
        println!(
            "Total: {}  (idle: {}, running: {}, leased: {}, cleanup: {}, corrupt: {})",
            filtered_count,
            summary.idle,
            summary.running,
            summary.leased,
            summary.cleanup,
            summary.corrupt,
        );
    }

    exit_codes::SUCCESS
}

// =============================================================================
// Lane Reset Command (TCK-00516)
// =============================================================================

/// Execute `apm2 fac lane reset <lane_id>`.
///
/// Resets a lane by deleting its workspace, target, and logs subdirectories
/// using `safe_rmtree_v1` (symlink-safe, boundary-enforced deletion).
///
/// # State Machine
///
/// - IDLE: resets workspace/target/logs, removes lease, remains IDLE.
/// - CORRUPT: resets workspace/target/logs, removes lease, transitions to IDLE.
/// - LEASED/CLEANUP: resets workspace/target/logs, removes lease, transitions
///   to IDLE.
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
            if !json_output {
                println!("Force-killing process {} for lane {}...", pid, args.lane_id);
            }
            if !kill_process_best_effort(pid) {
                let corrupt_reason = format!(
                    "failed to kill process {} for lane {} -- process may still be running or PID was reused",
                    pid, args.lane_id
                );
                persist_corrupt_lease(&manager, &args.lane_id, &corrupt_reason, json_output);
                return output_error(
                    json_output,
                    "kill_failed",
                    &corrupt_reason,
                    exit_codes::GENERIC_ERROR,
                );
            }
        }
    }

    // Perform safe deletion of workspace, target, and logs (under lock)
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

    let subdirs = ["workspace", "target", "logs"];
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
                if !json_output {
                    println!(
                        "  Deleted {}/{}: {} files, {} dirs",
                        args.lane_id, subdir, files_deleted, dirs_deleted
                    );
                }
            },
            Ok(SafeRmtreeOutcome::AlreadyAbsent) => {
                if !json_output {
                    println!("  {}/{}: already absent", args.lane_id, subdir);
                }
            },
            Err(e) => {
                let receipt = RefusedDeleteReceipt {
                    root: subdir_path.clone(),
                    allowed_parent: lanes_root.to_path_buf(),
                    reason: e.to_string(),
                    mark_corrupt: true,
                };
                refused_receipts.push(receipt);

                if !json_output {
                    eprintln!("  ERROR deleting {}/{}: {e}", args.lane_id, subdir);
                }
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
        persist_corrupt_lease(&manager, &args.lane_id, &corrupt_reason, json_output);

        if json_output {
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
        } else {
            eprintln!("Lane {} marked CORRUPT: {corrupt_reason}", args.lane_id);
        }

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

    // Re-create the empty subdirectories for the reset lane so it is
    // ready for reuse. This calls ensure_directories() which re-inits
    // all lanes, not just the reset lane. This is acceptable because
    // ensure_directories is idempotent (mkdir -p semantics) and only
    // creates directories that don't already exist.
    if let Err(e) = manager.ensure_directories() {
        if !json_output {
            eprintln!("Warning: failed to re-create lane directories: {e}");
        }
    }

    // Lock is released here when _lock_guard drops.

    if json_output {
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
    } else {
        println!(
            "Lane {} reset to IDLE ({} files, {} dirs deleted)",
            args.lane_id, total_files, total_dirs
        );
    }

    exit_codes::SUCCESS
}

/// Persist a CORRUPT lease to the lane directory so that `lane_status`
/// reports CORRUPT even after restart.
///
/// This is best-effort: if the lease write fails, a warning is printed
/// but the overall CORRUPT error flow continues (fail-closed: the lane
/// is already in a bad state).
fn persist_corrupt_lease(manager: &LaneManager, lane_id: &str, reason: &str, json_output: bool) {
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
                if !json_output {
                    eprintln!("  Warning: failed to persist CORRUPT lease for lane {lane_id}: {e}");
                }
            }
        },
        Err(e) => {
            if !json_output {
                eprintln!("  Warning: failed to create CORRUPT lease for lane {lane_id}: {e}");
            }
        },
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

/// Output an error in the appropriate format.
fn output_error(json_output: bool, code: &str, message: &str, exit_code: u8) -> u8 {
    if json_output {
        let error = ErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
        };
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&error).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        eprintln!("Error: {message}");
    }
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
    fn test_review_prompt_command_sequence_parses_with_verdict_surface() {
        assert_fac_command_parses(&["fac", "review", "prepare", "--json"]);
        assert_fac_command_parses(&[
            "fac",
            "review",
            "publish",
            "--type",
            "security",
            "--body-file",
            "/tmp/security_findings.md",
            "--json",
        ]);
        assert_fac_command_parses(&[
            "fac",
            "review",
            "publish",
            "--type",
            "code-quality",
            "--body-file",
            "/tmp/code_quality_findings.md",
            "--json",
        ]);
        assert_fac_command_parses(&["fac", "review", "findings", "--json"]);
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
}
