//! CI orchestration commands.
//!
//! This module provides a Rust-native replacement for shell-based CI
//! orchestration. It executes CI tasks as a dependency graph with bounded
//! execution under `systemd-run --user`, heartbeat telemetry, and structured
//! artifacts.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand, ValueEnum};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::exit_codes::codes as exit_codes;

const FAC_OVH_HOSTNAME: &str = "rust-forge-01";
const DEFAULT_HEARTBEAT_SECONDS: u64 = 1;
const DEFAULT_BOUNDED_TIMEOUT_SECONDS: u64 = 4800;
const DEFAULT_BOUNDED_KILL_AFTER_SECONDS: u64 = 30;
const DEFAULT_BOUNDED_MEMORY_MAX: &str = "64G";
const DEFAULT_BOUNDED_PIDS_MAX: u64 = 8192;
const DEFAULT_BOUNDED_CPU_QUOTA: &str = "1600%";
const DEFAULT_ARTIFACTS_DIR: &str = "target/ci/runs";
const DEFAULT_REUSE_STORE: &str = "target/ci/reuse-store";
const DEFAULT_HEAVY_LANE_TOKENS: usize = 1;
const DEFAULT_TREND_WINDOW_RUNS: usize = 5;
const DEFAULT_TREND_FAIL_COUNT: usize = 3;
const STARVATION_PROMOTION_TICKS: u64 = 5;
const BOUNDED_ENTRY_TOKEN_ENV: &str = "APM2_CI_BOUNDED_ENTRY_TOKEN";
const COUNTERMETRIC_LOCK_WAIT_WARN: f64 = 0.15;
const COUNTERMETRIC_LOCK_WAIT_FAIL: f64 = 0.30;
const COUNTERMETRIC_QUEUE_DELAY_WARN_MS: u128 = 5_000;
const COUNTERMETRIC_QUEUE_DELAY_FAIL_MS: u128 = 15_000;
const SUMMARY_SCHEMA: &str = "apm2.ci.run_summary.v2";
const SUMMARY_SCHEMA_VERSION: &str = "2.0.0";
const MANIFEST_SCHEMA: &str = "apm2.ci.run_manifest.v2";
const MANIFEST_SCHEMA_VERSION: &str = "2.0.0";
const COUNTERMETRICS_SCHEMA: &str = "apm2.ci.countermetrics.v2";
const COUNTERMETRICS_SCHEMA_VERSION: &str = "2.0.0";
const REUSE_RECEIPT_SCHEMA: &str = "apm2.ci.task_reuse_receipt.v2";
const REUSE_RECEIPT_SCHEMA_VERSION: &str = "2.0.0";
const REUSE_EVENT_SCHEMA: &str = "apm2.ci.reuse_event.v2";
const REUSE_EVENT_SCHEMA_VERSION: &str = "2.0.0";
const TREND_HISTORY_SCHEMA: &str = "apm2.ci.countermetrics_history.v2";
const TREND_HISTORY_SCHEMA_VERSION: &str = "2.0.0";

/// CI command group.
#[derive(Debug, Args)]
pub struct CiCommand {
    #[command(subcommand)]
    pub subcommand: CiSubcommand,
}

/// CI subcommands.
#[derive(Debug, Subcommand)]
pub enum CiSubcommand {
    /// Validate `systemd-run --user` and cgroup prerequisites.
    Preflight(PreflightArgs),
    /// Run CI in one bounded unit with dependency-graph parallelism.
    Run(RunArgs),
    /// Print resolved task graph for the selected profile.
    Explain(ExplainArgs),
}

/// Arguments for `apm2 ci preflight`.
#[derive(Debug, Args)]
pub struct PreflightArgs {
    /// Emit JSON output.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `apm2 ci run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// CI profile defining task surface and budget target.
    #[arg(long, value_enum, default_value_t = CiProfileArg::LocalFull)]
    pub profile: CiProfileArg,

    /// Maximum wall time for bounded unit.
    #[arg(long, default_value_t = DEFAULT_BOUNDED_TIMEOUT_SECONDS)]
    pub bounded_timeout_seconds: u64,

    /// TERM -> KILL escalation delay.
    #[arg(long, default_value_t = DEFAULT_BOUNDED_KILL_AFTER_SECONDS)]
    pub bounded_kill_after_seconds: u64,

    /// `MemoryMax` for the transient unit.
    #[arg(long, default_value = DEFAULT_BOUNDED_MEMORY_MAX)]
    pub bounded_memory_max: String,

    /// `TasksMax` for the transient unit.
    #[arg(long, default_value_t = DEFAULT_BOUNDED_PIDS_MAX)]
    pub bounded_pids_max: u64,

    /// `CPUQuota` for the transient unit.
    #[arg(long, default_value = DEFAULT_BOUNDED_CPU_QUOTA)]
    pub bounded_cpu_quota: String,

    /// Health-check heartbeat interval.
    #[arg(long, default_value_t = DEFAULT_HEARTBEAT_SECONDS)]
    pub heartbeat_seconds: u64,

    /// Task log streaming mode.
    #[arg(long, value_enum, default_value_t = CiLogModeArg::Dual)]
    pub log_mode: CiLogModeArg,

    /// Root directory for CI artifacts.
    #[arg(long, default_value = DEFAULT_ARTIFACTS_DIR)]
    pub artifacts_dir: PathBuf,

    /// Maximum number of concurrently running tasks.
    #[arg(long)]
    pub max_parallel: Option<usize>,

    /// Maximum concurrent heavy (Cargo-contending) lanes.
    #[arg(long, default_value_t = DEFAULT_HEAVY_LANE_TOKENS)]
    pub heavy_lane_tokens: usize,

    /// Task reuse policy.
    #[arg(long, value_enum, default_value_t = CiReuseModeArg::Strict)]
    pub reuse_mode: CiReuseModeArg,

    /// Path to strict digest-addressed task reuse store.
    #[arg(long, default_value = DEFAULT_REUSE_STORE)]
    pub reuse_store: PathBuf,

    /// Countermetrics budget enforcement policy.
    #[arg(long, value_enum, default_value_t = CiCountermetricsModeArg::Soft)]
    pub countermetrics_mode: CiCountermetricsModeArg,

    /// Trailing run window for countermetric trend evaluation.
    #[arg(long, default_value_t = DEFAULT_TREND_WINDOW_RUNS)]
    pub trend_window_runs: usize,

    /// Number of breaches required to fail when warmup has completed.
    #[arg(long, default_value_t = DEFAULT_TREND_FAIL_COUNT)]
    pub trend_fail_count: usize,
}

/// Arguments for `apm2 ci explain`.
#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// CI profile defining task surface and budget target.
    #[arg(long, value_enum, default_value_t = CiProfileArg::LocalFull)]
    pub profile: CiProfileArg,
}

/// CI profile selector.
#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CiProfileArg {
    /// Fast PR profile (target <= 2 minutes).
    GithubPrFast,
    /// Deep profile for main and merge-group validation.
    GithubDeep,
    /// Slow lane profile for heavyweight non-gating checks.
    GithubSlowLane,
    /// Full local profile with all checks.
    LocalFull,
}

impl CiProfileArg {
    const fn budget_target_seconds(self) -> u64 {
        match self {
            Self::GithubPrFast => 120,
            Self::GithubDeep | Self::LocalFull => 5400,
            Self::GithubSlowLane => 10_800,
        }
    }
}

/// Console/artifact log mode.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CiLogModeArg {
    /// Concise console output plus detailed artifact logs.
    Dual,
    /// Minimal console output with detailed artifact logs only.
    StructuredOnly,
}

/// Task reuse behavior.
#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CiReuseModeArg {
    /// Disable digest-addressed task reuse.
    Off,
    /// Enforce strict fail-closed reuse with receipt verification.
    Strict,
}

/// Countermetric gate behavior.
#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CiCountermetricsModeArg {
    /// Collect no countermetric gate decisions.
    Off,
    /// Evaluate with warmup and soft trend gate.
    Soft,
    /// Fail immediately on countermetric hard threshold breach.
    Hard,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum TaskClass {
    CheapParallel,
    CargoHeavy,
}

#[derive(Debug)]
enum TaskKind {
    Command(CommandSpec),
    Builtin(BuiltinTask),
}

#[derive(Debug, Clone)]
enum BuiltinTask {
    HostToolsCheck { required_tools: Vec<String> },
}

#[derive(Debug)]
struct CommandSpec {
    program: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
}

#[derive(Debug)]
struct TaskSpec {
    id: String,
    lane: String,
    class: TaskClass,
    deps: Vec<String>,
    declared_inputs: Vec<String>,
    kind: TaskKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum TaskState {
    Pass,
    Fail,
}

#[derive(Debug, Serialize)]
struct TaskSummary {
    id: String,
    lane: String,
    class: TaskClass,
    state: TaskState,
    exit_code: i32,
    duration_ms: u128,
    queue_delay_ms: u128,
    lock_wait_ms: u128,
    reused: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reuse_receipt_path: Option<String>,
    log_path: String,
    max_rss_kib: Option<u64>,
    max_threads: Option<u64>,
}

#[derive(Debug)]
struct TaskOutcome {
    summary: TaskSummary,
}

#[derive(Debug)]
struct Plan {
    profile: CiProfileArg,
    tasks: Vec<TaskSpec>,
}

#[derive(Debug)]
struct RunContext {
    repo_root: PathBuf,
    artifacts_root: PathBuf,
    run_id: String,
    run_dir: PathBuf,
    events_path: PathBuf,
    reuse_events_path: PathBuf,
    manifest_v2_path: PathBuf,
    summary_v2_path: PathBuf,
    countermetrics_v2_path: PathBuf,
    tasks_dir: PathBuf,
    heartbeat_seconds: u64,
    max_parallel: usize,
    heavy_lane_tokens: usize,
    log_mode: CiLogModeArg,
    reuse_mode: CiReuseModeArg,
    reuse_store: PathBuf,
    countermetrics_mode: CiCountermetricsModeArg,
    trend_window_runs: usize,
    trend_fail_count: usize,
    git_head: String,
    tracked_clean: bool,
    toolchain_fingerprint: String,
}

#[derive(Debug, Serialize)]
struct PreflightReport {
    hostname: String,
    expected_hostname: String,
    xdg_runtime_dir: String,
    dbus_session_bus_address: String,
    user_bus_socket: String,
    user_bus_socket_exists: bool,
    cgroup_v2_available: bool,
    systemd_run_user_ok: bool,
}

#[derive(Debug, Serialize)]
struct RunSummary {
    schema: &'static str,
    schema_version: &'static str,
    profile: CiProfileArg,
    run_id: String,
    run_dir: String,
    budget_target_seconds: u64,
    budget_actual_seconds: u64,
    budget_breach: bool,
    passed: bool,
    tasks: Vec<TaskSummary>,
    countermetrics: CountermetricsV2,
}

#[derive(Debug)]
struct SchedulerState {
    pending: BTreeMap<String, TaskSpec>,
    running: HashMap<String, RunningTaskState>,
    completed: HashMap<String, TaskOutcome>,
    ready_since_tick: HashMap<String, u64>,
    ready_since_instant: HashMap<String, Instant>,
}

#[derive(Debug)]
struct WorkerResult {
    id: String,
    lane: String,
    class: TaskClass,
    started_at: Instant,
    ended_at: Instant,
    exit_code: i32,
    queue_delay_ms: u128,
    lock_wait_ms: u128,
    reused: bool,
    failure_reason: Option<String>,
    task_digest: String,
    reuse_receipt_path: Option<PathBuf>,
    max_rss_kib: Option<u64>,
    max_threads: Option<u64>,
    log_path: PathBuf,
}

#[derive(Debug, Serialize)]
struct EventEnvelope {
    ts_unix_ms: u128,
    event: String,
    fields: serde_json::Value,
}

#[derive(Debug)]
struct RunningTaskState {
    class: TaskClass,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TaskReuseReceiptV2 {
    schema: String,
    schema_version: String,
    run_id: String,
    profile: CiProfileArg,
    task_id: String,
    task_class: TaskClass,
    task_digest: String,
    state: TaskState,
    exit_code: i32,
    log_digest: String,
    toolchain_fingerprint: String,
    git_head: String,
    tracked_clean: bool,
    created_unix_ms: u128,
}

#[derive(Debug, Serialize)]
struct TaskReuseEventV2 {
    schema: &'static str,
    schema_version: &'static str,
    run_id: String,
    task_id: String,
    task_digest: String,
    action: &'static str,
    reuse_receipt_path: String,
    created_unix_ms: u128,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CountermetricsHistoryRecordV2 {
    schema: String,
    schema_version: String,
    run_id: String,
    profile: CiProfileArg,
    lock_wait_ratio: f64,
    queue_delay_p95_ms: u128,
    breach: bool,
    created_unix_ms: u128,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize, Clone)]
struct CountermetricsV2 {
    schema: &'static str,
    schema_version: &'static str,
    lock_wait_ratio: f64,
    queue_delay_p95_ms: u128,
    artifact_completeness_ratio: f64,
    warmup_active: bool,
    trend_window_runs: usize,
    trend_fail_count: usize,
    trend_breach_count: usize,
    history_runs_considered: usize,
    lock_wait_warn_breach: bool,
    lock_wait_fail_breach: bool,
    queue_delay_warn_breach: bool,
    queue_delay_fail_breach: bool,
    artifact_completeness_fail_breach: bool,
    gate_failed: bool,
}

/// Execute CI command.
pub fn run_ci(cmd: &CiCommand) -> u8 {
    match &cmd.subcommand {
        CiSubcommand::Preflight(args) => run_preflight(args),
        CiSubcommand::Run(args) => run_ci_suite(args),
        CiSubcommand::Explain(args) => run_explain(args),
    }
}

fn run_preflight(args: &PreflightArgs) -> u8 {
    match preflight() {
        Ok(report) => {
            if args.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(json) => println!("{json}"),
                    Err(err) => eprintln!("ERROR: failed to render JSON preflight report: {err}"),
                }
            } else {
                println!("Preflight report");
                println!("  Hostname:                {}", report.hostname);
                println!("  Expected (fac-ovh):      {}", report.expected_hostname);
                println!("  XDG_RUNTIME_DIR:         {}", report.xdg_runtime_dir);
                println!(
                    "  DBUS_SESSION_BUS_ADDRESS:{}",
                    report.dbus_session_bus_address
                );
                println!("  User bus socket:         {}", report.user_bus_socket);
                println!("  Cgroup v2:               {}", report.cgroup_v2_available);
                println!("  systemd-run --user:      {}", report.systemd_run_user_ok);
                println!("Preflight passed: systemd-run --user is functional");
            }
            exit_codes::SUCCESS
        },
        Err(err) => {
            eprintln!("ERROR: preflight failed: {err}");
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_explain(args: &ExplainArgs) -> u8 {
    let repo_root = match resolve_repo_root() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("ERROR: failed to resolve repository root: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    let plan = build_plan(args.profile, &repo_root);
    if let Err(err) = validate_plan(&plan) {
        eprintln!("ERROR: invalid CI plan: {err}");
        return exit_codes::GENERIC_ERROR;
    }

    println!("CI plan for profile {:?}", args.profile);
    println!("Budget target: {}s", args.profile.budget_target_seconds());
    for task in &plan.tasks {
        println!("- {} [{}]", task.id, task.lane);
        if task.deps.is_empty() {
            println!("  deps: <none>");
        } else {
            println!("  deps: {}", task.deps.join(", "));
        }
        match &task.kind {
            TaskKind::Builtin(BuiltinTask::HostToolsCheck { .. }) => {
                println!("  cmd: builtin::host_tools_check");
            },
            TaskKind::Command(spec) => {
                println!("  cmd: {}", format_command_for_display(spec));
            },
        }
    }

    exit_codes::SUCCESS
}

fn run_ci_suite(args: &RunArgs) -> u8 {
    let inside_bounded = match detect_bounded_entry_context() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("ERROR: invalid bounded-entry context: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };
    let _bounded_cleanup_guard = BoundedCgroupCleanupGuard::new(inside_bounded);

    let repo_root = match resolve_repo_root() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("ERROR: failed to resolve repository root: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    if args.heartbeat_seconds == 0 {
        eprintln!("ERROR: --heartbeat-seconds must be > 0");
        return exit_codes::VALIDATION_ERROR;
    }

    if args.bounded_timeout_seconds == 0
        || args.bounded_kill_after_seconds == 0
        || args.bounded_pids_max == 0
    {
        eprintln!("ERROR: bounded timeout/kill-after/pids limits must be positive values");
        return exit_codes::VALIDATION_ERROR;
    }
    if args.heavy_lane_tokens == 0 {
        eprintln!("ERROR: --heavy-lane-tokens must be > 0");
        return exit_codes::VALIDATION_ERROR;
    }
    if args.trend_window_runs == 0 || args.trend_fail_count == 0 {
        eprintln!("ERROR: trend window and fail count must be > 0");
        return exit_codes::VALIDATION_ERROR;
    }

    let max_parallel = resolve_max_parallel(args.max_parallel);

    if !inside_bounded {
        let preflight_report = match preflight() {
            Ok(report) => report,
            Err(err) => {
                eprintln!("ERROR: preflight failed: {err}");
                return exit_codes::GENERIC_ERROR;
            },
        };

        println!(
            "INFO: Preflight passed: systemd-run --user is functional (host: {}, expected fac-ovh host: {})",
            preflight_report.hostname, preflight_report.expected_hostname
        );

        return run_inside_bounded_unit(args, &repo_root, max_parallel);
    }

    let run_ctx = match create_run_context(args, &repo_root, max_parallel) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("ERROR: failed to initialize CI run directories: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    println!("INFO: === Rust CI Orchestrator ===");
    println!("INFO: Repo root: {}", run_ctx.repo_root.display());
    println!("INFO: Run ID: {}", run_ctx.run_id);
    println!("INFO: Run dir: {}", run_ctx.run_dir.display());
    println!("INFO: Profile: {:?}", args.profile);
    println!("INFO: Max parallel tasks: {}", run_ctx.max_parallel);
    println!("INFO: Heavy lane tokens: {}", run_ctx.heavy_lane_tokens);

    if let Err(err) = write_manifest(&run_ctx, args) {
        eprintln!("ERROR: failed to write run manifest: {err}");
        return exit_codes::GENERIC_ERROR;
    }

    let plan = build_plan(args.profile, &run_ctx.repo_root);
    if let Err(err) = validate_plan(&plan) {
        eprintln!("ERROR: invalid CI plan: {err}");
        return exit_codes::GENERIC_ERROR;
    }

    let start = Instant::now();
    let state = match execute_plan(&run_ctx, &plan) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("ERROR: CI execution failed: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    let elapsed_seconds = start.elapsed().as_secs();
    let mut summaries = state
        .completed
        .into_values()
        .map(|outcome| outcome.summary)
        .collect::<Vec<_>>();
    summaries.sort_by(|a, b| a.id.cmp(&b.id));

    let task_passed = summaries
        .iter()
        .all(|summary| summary.state == TaskState::Pass);
    let mut summary = RunSummary {
        schema: SUMMARY_SCHEMA,
        schema_version: SUMMARY_SCHEMA_VERSION,
        profile: args.profile,
        run_id: run_ctx.run_id.clone(),
        run_dir: run_ctx.run_dir.display().to_string(),
        budget_target_seconds: args.profile.budget_target_seconds(),
        budget_actual_seconds: elapsed_seconds,
        budget_breach: elapsed_seconds > args.profile.budget_target_seconds(),
        passed: task_passed,
        tasks: summaries,
        countermetrics: CountermetricsV2 {
            schema: COUNTERMETRICS_SCHEMA,
            schema_version: COUNTERMETRICS_SCHEMA_VERSION,
            lock_wait_ratio: 0.0,
            queue_delay_p95_ms: 0,
            artifact_completeness_ratio: 0.0,
            warmup_active: true,
            trend_window_runs: run_ctx.trend_window_runs,
            trend_fail_count: run_ctx.trend_fail_count,
            trend_breach_count: 0,
            history_runs_considered: 0,
            lock_wait_warn_breach: false,
            lock_wait_fail_breach: false,
            queue_delay_warn_breach: false,
            queue_delay_fail_breach: false,
            artifact_completeness_fail_breach: false,
            gate_failed: false,
        },
    };

    let prewrite_artifact_ratio =
        compute_artifact_completeness_ratio(&run_ctx, &summary.tasks, false);
    let mut countermetrics =
        evaluate_countermetrics(&run_ctx, &summary.tasks, prewrite_artifact_ratio);
    summary.countermetrics = countermetrics.clone();
    summary.passed = task_passed && !countermetrics.gate_failed;

    if let Err(err) = write_summary(&run_ctx, &summary) {
        eprintln!("ERROR: failed to write summary: {err}");
        return exit_codes::GENERIC_ERROR;
    }
    if let Err(err) = write_countermetrics(&run_ctx, &countermetrics) {
        eprintln!("ERROR: failed to write countermetrics: {err}");
        return exit_codes::GENERIC_ERROR;
    }

    let final_artifact_ratio = compute_artifact_completeness_ratio(&run_ctx, &summary.tasks, true);
    if (final_artifact_ratio - countermetrics.artifact_completeness_ratio).abs() > f64::EPSILON {
        countermetrics = evaluate_countermetrics(&run_ctx, &summary.tasks, final_artifact_ratio);
    }
    if let Err(err) = persist_countermetric_history(&run_ctx, &mut countermetrics, args.profile) {
        eprintln!("ERROR: failed to persist countermetric history: {err}");
        return exit_codes::GENERIC_ERROR;
    }
    summary.countermetrics = countermetrics.clone();
    summary.passed = task_passed && !countermetrics.gate_failed;

    if let Err(err) = write_summary(&run_ctx, &summary) {
        eprintln!("ERROR: failed to rewrite summary: {err}");
        return exit_codes::GENERIC_ERROR;
    }
    if let Err(err) = write_countermetrics(&run_ctx, &countermetrics) {
        eprintln!("ERROR: failed to rewrite countermetrics: {err}");
        return exit_codes::GENERIC_ERROR;
    }

    print_summary(&summary);

    if !summary.passed {
        print_failure_tails(&summary);
        eprintln!("ERROR: CI suite failed.");
        return exit_codes::GENERIC_ERROR;
    }

    if summary.budget_breach {
        eprintln!(
            "WARN: CI budget breached (target={}s actual={}s)",
            summary.budget_target_seconds, summary.budget_actual_seconds
        );
    }

    println!("INFO: CI suite passed.");
    exit_codes::SUCCESS
}

fn resolve_max_parallel(explicit: Option<usize>) -> usize {
    if let Some(value) = explicit {
        return value.max(1);
    }

    std::thread::available_parallelism()
        .map_or(4, |v| v.get().max(1))
        .min(64)
}

fn create_run_context(
    args: &RunArgs,
    repo_root: &Path,
    max_parallel: usize,
) -> Result<RunContext, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock error: {err}"))?;

    let run_id = format!(
        "{}-{}-{}",
        std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_string()),
        std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".to_string()),
        now.as_secs()
    );

    let artifacts_root = if args.artifacts_dir.is_absolute() {
        args.artifacts_dir.clone()
    } else {
        repo_root.join(&args.artifacts_dir)
    };
    let reuse_store = if args.reuse_store.is_absolute() {
        args.reuse_store.clone()
    } else {
        repo_root.join(&args.reuse_store)
    };

    let run_dir = artifacts_root.join(&run_id);
    let tasks_dir = run_dir.join("tasks");
    fs::create_dir_all(&tasks_dir)
        .map_err(|err| format!("failed to create {}: {err}", tasks_dir.display()))?;
    fs::create_dir_all(&reuse_store).map_err(|err| {
        format!(
            "failed to create reuse store {}: {err}",
            reuse_store.display()
        )
    })?;

    let events_path = run_dir.join("events.ndjson");
    let reuse_events_path = run_dir.join("reuse_receipts.v2.ndjson");
    let manifest_v2_path = run_dir.join("manifest.v2.json");
    let summary_v2_path = run_dir.join("summary.v2.json");
    let countermetrics_v2_path = run_dir.join("countermetrics.v2.json");
    let git_head = resolve_git_head(repo_root)?;
    let tracked_clean = is_tracked_tree_clean(repo_root)?;
    let toolchain_fingerprint = compute_toolchain_fingerprint()?;

    Ok(RunContext {
        repo_root: repo_root.to_path_buf(),
        artifacts_root,
        run_id,
        run_dir,
        events_path,
        reuse_events_path,
        manifest_v2_path,
        summary_v2_path,
        countermetrics_v2_path,
        tasks_dir,
        heartbeat_seconds: args.heartbeat_seconds,
        max_parallel,
        heavy_lane_tokens: args.heavy_lane_tokens,
        log_mode: args.log_mode,
        reuse_mode: args.reuse_mode,
        reuse_store,
        countermetrics_mode: args.countermetrics_mode,
        trend_window_runs: args.trend_window_runs,
        trend_fail_count: args.trend_fail_count,
        git_head,
        tracked_clean,
        toolchain_fingerprint,
    })
}

fn write_manifest(run_ctx: &RunContext, args: &RunArgs) -> Result<(), String> {
    #[derive(Serialize)]
    struct Manifest {
        run_id: String,
        profile: CiProfileArg,
        repo_root: String,
        heartbeat_seconds: u64,
        max_parallel: usize,
        bounded_timeout_seconds: u64,
        bounded_kill_after_seconds: u64,
        bounded_memory_max: String,
        bounded_pids_max: u64,
        bounded_cpu_quota: String,
    }
    #[derive(Serialize)]
    struct ManifestV2 {
        schema: &'static str,
        schema_version: &'static str,
        run_id: String,
        profile: CiProfileArg,
        repo_root: String,
        artifacts_root: String,
        heartbeat_seconds: u64,
        max_parallel: usize,
        heavy_lane_tokens: usize,
        reuse_mode: CiReuseModeArg,
        reuse_store: String,
        countermetrics_mode: CiCountermetricsModeArg,
        trend_window_runs: usize,
        trend_fail_count: usize,
        bounded_timeout_seconds: u64,
        bounded_kill_after_seconds: u64,
        bounded_memory_max: String,
        bounded_pids_max: u64,
        bounded_cpu_quota: String,
        git_head: String,
        tracked_clean: bool,
        toolchain_fingerprint: String,
    }

    let manifest = Manifest {
        run_id: run_ctx.run_id.clone(),
        profile: args.profile,
        repo_root: run_ctx.repo_root.display().to_string(),
        heartbeat_seconds: args.heartbeat_seconds,
        max_parallel: run_ctx.max_parallel,
        bounded_timeout_seconds: args.bounded_timeout_seconds,
        bounded_kill_after_seconds: args.bounded_kill_after_seconds,
        bounded_memory_max: args.bounded_memory_max.clone(),
        bounded_pids_max: args.bounded_pids_max,
        bounded_cpu_quota: args.bounded_cpu_quota.clone(),
    };
    let manifest_v2 = ManifestV2 {
        schema: MANIFEST_SCHEMA,
        schema_version: MANIFEST_SCHEMA_VERSION,
        run_id: run_ctx.run_id.clone(),
        profile: args.profile,
        repo_root: run_ctx.repo_root.display().to_string(),
        artifacts_root: run_ctx.artifacts_root.display().to_string(),
        heartbeat_seconds: args.heartbeat_seconds,
        max_parallel: run_ctx.max_parallel,
        heavy_lane_tokens: run_ctx.heavy_lane_tokens,
        reuse_mode: run_ctx.reuse_mode,
        reuse_store: run_ctx.reuse_store.display().to_string(),
        countermetrics_mode: run_ctx.countermetrics_mode,
        trend_window_runs: run_ctx.trend_window_runs,
        trend_fail_count: run_ctx.trend_fail_count,
        bounded_timeout_seconds: args.bounded_timeout_seconds,
        bounded_kill_after_seconds: args.bounded_kill_after_seconds,
        bounded_memory_max: args.bounded_memory_max.clone(),
        bounded_pids_max: args.bounded_pids_max,
        bounded_cpu_quota: args.bounded_cpu_quota.clone(),
        git_head: run_ctx.git_head.clone(),
        tracked_clean: run_ctx.tracked_clean,
        toolchain_fingerprint: run_ctx.toolchain_fingerprint.clone(),
    };

    let manifest_path = run_ctx.run_dir.join("manifest.json");
    let json = serde_json::to_vec_pretty(&manifest)
        .map_err(|err| format!("failed to serialize manifest: {err}"))?;
    atomic_write(&manifest_path, &json)?;
    let json_v2 = serde_json::to_vec_pretty(&manifest_v2)
        .map_err(|err| format!("failed to serialize manifest.v2: {err}"))?;
    atomic_write(&run_ctx.manifest_v2_path, &json_v2)
}

fn write_summary(run_ctx: &RunContext, summary: &RunSummary) -> Result<(), String> {
    let summary_path = run_ctx.run_dir.join("summary.json");
    let json = serde_json::to_vec_pretty(summary)
        .map_err(|err| format!("failed to serialize summary: {err}"))?;
    atomic_write(&summary_path, &json)?;
    atomic_write(&run_ctx.summary_v2_path, &json)
}

fn write_countermetrics(
    run_ctx: &RunContext,
    countermetrics: &CountermetricsV2,
) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(countermetrics)
        .map_err(|err| format!("failed to serialize countermetrics: {err}"))?;
    atomic_write(&run_ctx.countermetrics_v2_path, &json)
}

fn print_summary(summary: &RunSummary) {
    println!();
    println!("INFO: === CI Summary ===");
    println!("INFO: Run dir: {}", summary.run_dir);
    println!(
        "INFO: Budget target={}s actual={}s breach={}",
        summary.budget_target_seconds, summary.budget_actual_seconds, summary.budget_breach
    );

    let mut ordered = summary.tasks.iter().collect::<Vec<_>>();
    ordered.sort_by(|a, b| a.id.cmp(&b.id));

    for task in ordered {
        let state = match task.state {
            TaskState::Pass => "PASS",
            TaskState::Fail => "FAIL",
        };
        println!(
            "  {:28} {:4} {:6}ms q={:5}ms lock={:5}ms reused={} {}",
            task.id,
            state,
            task.duration_ms,
            task.queue_delay_ms,
            task.lock_wait_ms,
            task.reused,
            task.log_path
        );
    }
    println!(
        "INFO: Countermetrics lock_wait_ratio={:.3} queue_delay_p95_ms={} artifact_completeness_ratio={:.3} gate_failed={} warmup={}",
        summary.countermetrics.lock_wait_ratio,
        summary.countermetrics.queue_delay_p95_ms,
        summary.countermetrics.artifact_completeness_ratio,
        summary.countermetrics.gate_failed,
        summary.countermetrics.warmup_active
    );
}

fn print_failure_tails(summary: &RunSummary) {
    let failures = summary
        .tasks
        .iter()
        .filter(|task| task.state == TaskState::Fail)
        .collect::<Vec<_>>();

    for task in failures {
        println!();
        eprintln!("WARN: === Failure Tail: {} ===", task.id);
        if let Ok(tail) = read_tail(Path::new(&task.log_path), 120) {
            eprintln!("{tail}");
        } else {
            eprintln!("WARN: unable to read failure tail from {}", task.log_path);
        }
    }
}

fn read_tail(path: &Path, max_lines: usize) -> Result<String, String> {
    let file = File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("read line: {err}"))?;
        lines.push(line);
        if lines.len() > max_lines {
            let _ = lines.remove(0);
        }
    }
    Ok(lines.join("\n"))
}

fn execute_plan(run_ctx: &RunContext, plan: &Plan) -> Result<SchedulerState, String> {
    let events_file = File::create(&run_ctx.events_path)
        .map_err(|err| format!("failed to create {}: {err}", run_ctx.events_path.display()))?;
    let reuse_events_file = File::create(&run_ctx.reuse_events_path).map_err(|err| {
        format!(
            "failed to create {}: {err}",
            run_ctx.reuse_events_path.display()
        )
    })?;

    let state = SchedulerState {
        pending: plan
            .tasks
            .iter()
            .map(|task| (task.id.clone(), clone_task(task)))
            .collect::<BTreeMap<_, _>>(),
        running: HashMap::new(),
        completed: HashMap::new(),
        ready_since_tick: HashMap::new(),
        ready_since_instant: HashMap::new(),
    };

    run_scheduler(
        run_ctx,
        state,
        &events_file,
        &reuse_events_file,
        plan.profile,
    )
}

fn run_scheduler(
    run_ctx: &RunContext,
    mut state: SchedulerState,
    events_file: &File,
    reuse_events_file: &File,
    profile: CiProfileArg,
) -> Result<SchedulerState, String> {
    let (tx, rx) = mpsc::channel::<WorkerResult>();
    let events_file = Arc::new(Mutex::new(
        events_file.try_clone().map_err(|err| err.to_string())?,
    ));
    let reuse_events_file =
        Arc::new(Mutex::new(reuse_events_file.try_clone().map_err(
            |err| format!("failed to clone reuse events file: {err}"),
        )?));
    let run_started_at = Instant::now();
    let mut tick: u64 = 0;

    loop {
        tick = tick.saturating_add(1);
        let loop_now = Instant::now();
        let blocked_ids = state
            .pending
            .iter()
            .filter_map(|(id, task)| {
                let all_deps_completed = task
                    .deps
                    .iter()
                    .all(|dep| state.completed.contains_key(dep));
                if !all_deps_completed {
                    return None;
                }

                let failed_deps = task
                    .deps
                    .iter()
                    .filter(|dep| {
                        state
                            .completed
                            .get(*dep)
                            .is_some_and(|outcome| outcome.summary.state == TaskState::Fail)
                    })
                    .cloned()
                    .collect::<Vec<_>>();

                if failed_deps.is_empty() {
                    None
                } else {
                    Some((id.clone(), failed_deps))
                }
            })
            .collect::<Vec<_>>();

        for (id, failed_deps) in blocked_ids {
            if let Some(task) = state.pending.remove(&id) {
                let task_log_path = run_ctx.tasks_dir.join(format!("{}.log", task.id));
                let blocked_message =
                    format!("blocked by failed dependency: {}", failed_deps.join(", "));
                fs::write(
                    &task_log_path,
                    format!(
                        "task_id={}\nlane={}\nstatus=FAIL\nreason={}\n",
                        task.id, task.lane, blocked_message
                    ),
                )
                .map_err(|err| {
                    format!(
                        "failed to write blocked task log {}: {err}",
                        task_log_path.display()
                    )
                })?;
                let queue_delay_ms = state.ready_since_instant.remove(&id).map_or(0, |ready_at| {
                    loop_now.saturating_duration_since(ready_at).as_millis()
                });
                state.ready_since_tick.remove(&id);

                let summary = TaskSummary {
                    id: task.id.clone(),
                    lane: task.lane,
                    class: task.class,
                    state: TaskState::Fail,
                    exit_code: 125,
                    duration_ms: 0,
                    queue_delay_ms,
                    lock_wait_ms: 0,
                    reused: false,
                    failure_reason: Some(blocked_message.clone()),
                    task_digest: None,
                    reuse_receipt_path: None,
                    log_path: task_log_path.display().to_string(),
                    max_rss_kib: None,
                    max_threads: None,
                };

                write_event(
                    &events_file,
                    "task_blocked",
                    serde_json::json!({
                        "task_id": summary.id,
                        "reason": blocked_message,
                        "log_path": summary.log_path,
                    }),
                )?;

                if matches!(run_ctx.log_mode, CiLogModeArg::Dual) {
                    println!("INFO: END   [{}] FAIL (blocked)", summary.id);
                }

                state
                    .completed
                    .insert(summary.id.clone(), TaskOutcome { summary });
            }
        }

        for (id, task) in &state.pending {
            let all_deps_passed = task.deps.iter().all(|dep| {
                state
                    .completed
                    .get(dep)
                    .is_some_and(|outcome| outcome.summary.state == TaskState::Pass)
            });
            if all_deps_passed {
                state.ready_since_tick.entry(id.clone()).or_insert(tick);
                state
                    .ready_since_instant
                    .entry(id.clone())
                    .or_insert(loop_now);
            }
        }

        let mut ready_ids = state
            .pending
            .iter()
            .filter(|(id, task)| {
                !state.running.contains_key(*id)
                    && task.deps.iter().all(|dep| {
                        state
                            .completed
                            .get(dep)
                            .is_some_and(|outcome| outcome.summary.state == TaskState::Pass)
                    })
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        ready_ids.sort_by(|left, right| {
            let Some(left_task) = state.pending.get(left) else {
                return left.cmp(right);
            };
            let Some(right_task) = state.pending.get(right) else {
                return left.cmp(right);
            };
            let left_ready_tick = *state.ready_since_tick.get(left).unwrap_or(&tick);
            let right_ready_tick = *state.ready_since_tick.get(right).unwrap_or(&tick);
            let left_wait_ticks = tick.saturating_sub(left_ready_tick);
            let right_wait_ticks = tick.saturating_sub(right_ready_tick);

            let left_starved = left_task.class == TaskClass::CargoHeavy
                && left_wait_ticks >= STARVATION_PROMOTION_TICKS;
            let right_starved = right_task.class == TaskClass::CargoHeavy
                && right_wait_ticks >= STARVATION_PROMOTION_TICKS;

            (
                !left_starved,
                left_task.class,
                left_ready_tick,
                left.as_str(),
            )
                .cmp(&(
                    !right_starved,
                    right_task.class,
                    right_ready_tick,
                    right.as_str(),
                ))
        });

        let mut available_slots = run_ctx.max_parallel.saturating_sub(state.running.len());
        let mut available_heavy_tokens = run_ctx.heavy_lane_tokens.saturating_sub(
            state
                .running
                .values()
                .filter(|running| running.class == TaskClass::CargoHeavy)
                .count(),
        );

        for id in ready_ids {
            if available_slots == 0 {
                break;
            }
            let Some(task_view) = state.pending.get(&id) else {
                continue;
            };
            if task_view.class == TaskClass::CargoHeavy && available_heavy_tokens == 0 {
                let wait_ticks =
                    tick.saturating_sub(*state.ready_since_tick.get(&id).unwrap_or(&tick));
                write_event(
                    &events_file,
                    "task_deferred_backpressure",
                    serde_json::json!({
                        "task_id": id,
                        "class": task_view.class,
                        "wait_ticks": wait_ticks,
                    }),
                )?;
                continue;
            }

            let Some(task) = state.pending.remove(&id) else {
                continue;
            };
            let task_log_path = run_ctx.tasks_dir.join(format!("{}.log", task.id));
            let ready_tick = state.ready_since_tick.remove(&id).unwrap_or(tick);
            let ready_instant = state.ready_since_instant.remove(&id).unwrap_or(loop_now);
            let queue_delay_ms = loop_now
                .saturating_duration_since(ready_instant)
                .as_millis();

            let task_digest = compute_task_digest(run_ctx, profile, &task, &state.completed)?;
            if run_ctx.reuse_mode == CiReuseModeArg::Strict {
                if let Some(reuse_receipt) =
                    load_reuse_receipt(run_ctx, profile, &task.id, &task_digest)?
                {
                    fs::write(
                        &task_log_path,
                        format!(
                            "task_id={}\nlane={}\nclass={:?}\nstatus=PASS\nreused=true\ntask_digest={}\nreuse_receipt={}\n",
                            task.id,
                            task.lane,
                            task.class,
                            task_digest,
                            reuse_receipt.path.display()
                        ),
                    )
                    .map_err(|err| {
                        format!(
                            "failed to write reused task log {}: {err}",
                            task_log_path.display()
                        )
                    })?;

                    let summary = TaskSummary {
                        id: task.id.clone(),
                        lane: task.lane.clone(),
                        class: task.class,
                        state: TaskState::Pass,
                        exit_code: 0,
                        duration_ms: 0,
                        queue_delay_ms,
                        lock_wait_ms: 0,
                        reused: true,
                        failure_reason: None,
                        task_digest: Some(task_digest.clone()),
                        reuse_receipt_path: Some(reuse_receipt.path.display().to_string()),
                        log_path: task_log_path.display().to_string(),
                        max_rss_kib: None,
                        max_threads: None,
                    };
                    write_event(
                        &events_file,
                        "task_reused",
                        serde_json::json!({
                            "task_id": summary.id,
                            "task_digest": task_digest,
                            "reuse_receipt_path": reuse_receipt.path,
                            "queue_delay_ms": queue_delay_ms,
                        }),
                    )?;
                    append_reuse_event(
                        &reuse_events_file,
                        &TaskReuseEventV2 {
                            schema: REUSE_EVENT_SCHEMA,
                            schema_version: REUSE_EVENT_SCHEMA_VERSION,
                            run_id: run_ctx.run_id.clone(),
                            task_id: task.id,
                            task_digest,
                            action: "reused",
                            reuse_receipt_path: reuse_receipt.path.display().to_string(),
                            created_unix_ms: now_unix_ms()?,
                        },
                    )?;
                    state
                        .completed
                        .insert(summary.id.clone(), TaskOutcome { summary });
                    continue;
                }
            }

            let tx_clone = tx.clone();
            let repo_root = run_ctx.repo_root.clone();
            let events_file_clone = Arc::clone(&events_file);
            let task_id = task.id.clone();
            let task_lane = task.lane.clone();
            let task_class = task.class;
            state
                .running
                .insert(task_id.clone(), RunningTaskState { class: task.class });
            available_slots = available_slots.saturating_sub(1);
            if task.class == TaskClass::CargoHeavy {
                available_heavy_tokens = available_heavy_tokens.saturating_sub(1);
            }

            write_event(
                &events_file_clone,
                "task_started",
                serde_json::json!({
                    "task_id": task.id,
                    "lane": task.lane,
                    "class": task.class,
                    "task_digest": task_digest,
                    "queue_delay_ms": queue_delay_ms,
                    "ready_tick": ready_tick,
                    "start_tick": tick,
                    "log_path": task_log_path.display().to_string(),
                }),
            )?;

            if matches!(run_ctx.log_mode, CiLogModeArg::Dual) {
                println!("INFO: START [{id}] class={task_class:?}");
            }

            thread::spawn(move || {
                let started_at = Instant::now();
                let worker_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_task(
                        task,
                        &repo_root,
                        &task_log_path,
                        started_at,
                        queue_delay_ms,
                        task_digest.clone(),
                    )
                }))
                .unwrap_or_else(|_| WorkerResult {
                    id: task_id.clone(),
                    lane: task_lane,
                    class: task_class,
                    started_at,
                    ended_at: Instant::now(),
                    exit_code: 126,
                    queue_delay_ms,
                    lock_wait_ms: 0,
                    reused: false,
                    failure_reason: Some("worker panic while executing task".to_string()),
                    task_digest,
                    reuse_receipt_path: None,
                    max_rss_kib: None,
                    max_threads: None,
                    log_path: task_log_path,
                });
                let _ = tx_clone.send(worker_result);
            });
        }

        if state.pending.is_empty() && state.running.is_empty() {
            break;
        }

        match rx.recv_timeout(Duration::from_secs(run_ctx.heartbeat_seconds)) {
            Ok(result) => {
                let mut summary = TaskSummary {
                    id: result.id.clone(),
                    lane: result.lane,
                    class: result.class,
                    state: if result.exit_code == 0 {
                        TaskState::Pass
                    } else {
                        TaskState::Fail
                    },
                    exit_code: result.exit_code,
                    duration_ms: result
                        .ended_at
                        .duration_since(result.started_at)
                        .as_millis(),
                    queue_delay_ms: result.queue_delay_ms,
                    lock_wait_ms: result.lock_wait_ms,
                    reused: result.reused,
                    failure_reason: result.failure_reason,
                    task_digest: Some(result.task_digest.clone()),
                    reuse_receipt_path: result
                        .reuse_receipt_path
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    log_path: result.log_path.display().to_string(),
                    max_rss_kib: result.max_rss_kib,
                    max_threads: result.max_threads,
                };

                if run_ctx.reuse_mode == CiReuseModeArg::Strict && summary.state == TaskState::Pass
                {
                    let receipt_path = store_reuse_receipt(run_ctx, profile, &summary)?;
                    append_reuse_event(
                        &reuse_events_file,
                        &TaskReuseEventV2 {
                            schema: REUSE_EVENT_SCHEMA,
                            schema_version: REUSE_EVENT_SCHEMA_VERSION,
                            run_id: run_ctx.run_id.clone(),
                            task_id: summary.id.clone(),
                            task_digest: summary.task_digest.clone().unwrap_or_default(),
                            action: "stored",
                            reuse_receipt_path: receipt_path.display().to_string(),
                            created_unix_ms: now_unix_ms()?,
                        },
                    )?;
                    summary.reuse_receipt_path = Some(receipt_path.display().to_string());
                }

                write_event(
                    &events_file,
                    "task_finished",
                    serde_json::json!({
                        "task_id": result.id,
                        "class": summary.class,
                        "state": summary.state,
                        "exit_code": summary.exit_code,
                        "duration_ms": summary.duration_ms,
                        "queue_delay_ms": summary.queue_delay_ms,
                        "lock_wait_ms": summary.lock_wait_ms,
                        "reused": summary.reused,
                        "task_digest": summary.task_digest,
                        "failure_reason": summary.failure_reason,
                        "max_rss_kib": summary.max_rss_kib,
                        "max_threads": summary.max_threads,
                        "log_path": summary.log_path,
                    }),
                )?;

                if matches!(run_ctx.log_mode, CiLogModeArg::Dual) {
                    println!(
                        "INFO: END   [{}] {} ({}) q={}ms lock={}ms reused={}",
                        summary.id,
                        if summary.state == TaskState::Pass {
                            "PASS"
                        } else {
                            "FAIL"
                        },
                        summary.exit_code,
                        summary.queue_delay_ms,
                        summary.lock_wait_ms,
                        summary.reused
                    );
                }

                state.running.remove(&summary.id);
                state
                    .completed
                    .insert(summary.id.clone(), TaskOutcome { summary });
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let completed = state.completed.len();
                let failed = state
                    .completed
                    .values()
                    .filter(|outcome| outcome.summary.state == TaskState::Fail)
                    .count();
                let running = state.running.len();
                let pending = state.pending.len();
                let elapsed = run_started_at.elapsed().as_secs();

                println!(
                    "HEALTH: elapsed={}s running={} pending={} passed={} failed={} heavy_running={} heavy_tokens={}",
                    elapsed,
                    running,
                    pending,
                    completed.saturating_sub(failed),
                    failed,
                    state
                        .running
                        .values()
                        .filter(|running| running.class == TaskClass::CargoHeavy)
                        .count(),
                    run_ctx.heavy_lane_tokens
                );

                write_event(
                    &events_file,
                    "heartbeat",
                    serde_json::json!({
                        "elapsed_seconds": elapsed,
                        "running": running,
                        "pending": pending,
                        "passed": completed.saturating_sub(failed),
                        "failed": failed,
                    }),
                )?;
            },
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if state.running.is_empty() {
                    break;
                }
                return Err("scheduler channel disconnected unexpectedly".to_string());
            },
        }
    }

    if !state.pending.is_empty() {
        let blocked = state
            .pending
            .values()
            .map(|task| task.id.clone())
            .collect::<Vec<_>>();
        return Err(format!(
            "CI plan contains unresolved dependency cycle(s), blocked tasks: {}",
            blocked.join(", ")
        ));
    }

    Ok(state)
}

fn run_task(
    task: TaskSpec,
    repo_root: &Path,
    task_log_path: &Path,
    started_at: Instant,
    queue_delay_ms: u128,
    task_digest: String,
) -> WorkerResult {
    let Ok(mut log_file) = File::create(task_log_path) else {
        return WorkerResult {
            id: task.id,
            lane: task.lane,
            class: task.class,
            started_at,
            ended_at: Instant::now(),
            exit_code: 127,
            queue_delay_ms,
            lock_wait_ms: 0,
            reused: false,
            failure_reason: Some("failed to create task log file".to_string()),
            task_digest,
            reuse_receipt_path: None,
            max_rss_kib: None,
            max_threads: None,
            log_path: task_log_path.to_path_buf(),
        };
    };

    let _ = writeln!(log_file, "task_id={}", task.id);
    let _ = writeln!(log_file, "lane={}", task.lane);
    let _ = writeln!(log_file, "class={:?}", task.class);
    let _ = writeln!(log_file, "task_digest={task_digest}");

    match task.kind {
        TaskKind::Builtin(builtin) => {
            let exit_code = run_builtin_task(builtin, &mut log_file);
            let ended_at = Instant::now();
            WorkerResult {
                id: task.id,
                lane: task.lane,
                class: task.class,
                started_at,
                ended_at,
                exit_code,
                queue_delay_ms,
                lock_wait_ms: 0,
                reused: false,
                failure_reason: None,
                task_digest,
                reuse_receipt_path: None,
                max_rss_kib: None,
                max_threads: None,
                log_path: task_log_path.to_path_buf(),
            }
        },
        TaskKind::Command(command) => {
            let _ = writeln!(log_file, "cmd={}", format_command_for_display(&command));

            let mut cmd = Command::new(&command.program);
            cmd.current_dir(repo_root)
                .args(&command.args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            for (key, value) in &command.env {
                cmd.env(key, value);
            }

            let mut child = match cmd.spawn() {
                Ok(child) => child,
                Err(err) => {
                    let _ = writeln!(log_file, "spawn_error={err}");
                    return WorkerResult {
                        id: task.id,
                        lane: task.lane,
                        class: task.class,
                        started_at,
                        ended_at: Instant::now(),
                        exit_code: 127,
                        queue_delay_ms,
                        lock_wait_ms: 0,
                        reused: false,
                        failure_reason: Some(format!("spawn error: {err}")),
                        task_digest,
                        reuse_receipt_path: None,
                        max_rss_kib: None,
                        max_threads: None,
                        log_path: task_log_path.to_path_buf(),
                    };
                },
            };

            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let log_handle = Arc::new(Mutex::new(log_file));
            let lock_wait_tracker = Arc::new(LockWaitTracker::default());

            let stdout_handle = stdout.map(|pipe| {
                let log_handle = Arc::clone(&log_handle);
                let lock_wait_tracker = Arc::clone(&lock_wait_tracker);
                thread::spawn(move || pipe_to_log(pipe, &log_handle, "stdout", &lock_wait_tracker))
            });
            let stderr_handle = stderr.map(|pipe| {
                let log_handle = Arc::clone(&log_handle);
                let lock_wait_tracker = Arc::clone(&lock_wait_tracker);
                thread::spawn(move || pipe_to_log(pipe, &log_handle, "stderr", &lock_wait_tracker))
            });

            let monitor_state = Arc::new(MonitorState::default());
            let monitor_stop = Arc::new(AtomicBool::new(false));
            let monitor_thread = {
                let monitor_state = Arc::clone(&monitor_state);
                let monitor_stop = Arc::clone(&monitor_stop);
                let pid = child.id();
                thread::spawn(move || monitor_process(pid, &monitor_state, &monitor_stop))
            };

            let status = child.wait();
            monitor_stop.store(true, Ordering::SeqCst);
            let _ = monitor_thread.join();

            let mut io_errors = Vec::new();
            if let Some(handle) = stdout_handle {
                match handle.join() {
                    Ok(Ok(())) => {},
                    Ok(Err(err)) => io_errors.push(format!("stdout log pipe error: {err}")),
                    Err(_) => io_errors.push("stdout log pipe panic".to_string()),
                }
            }
            if let Some(handle) = stderr_handle {
                match handle.join() {
                    Ok(Ok(())) => {},
                    Ok(Err(err)) => io_errors.push(format!("stderr log pipe error: {err}")),
                    Err(_) => io_errors.push("stderr log pipe panic".to_string()),
                }
            }

            let ended_at = Instant::now();
            let lock_wait_ms = lock_wait_tracker.finish(ended_at);
            let mut failure_reason = None;
            let exit_code = if io_errors.is_empty() {
                status.map_or(1, |status| status.code().unwrap_or(1))
            } else {
                failure_reason = Some(io_errors.join("; "));
                125
            };
            {
                if let Ok(mut file) = log_handle.lock() {
                    let _ = writeln!(file, "exit_code={exit_code}");
                    let _ = writeln!(file, "queue_delay_ms={queue_delay_ms}");
                    let _ = writeln!(file, "lock_wait_ms={lock_wait_ms}");
                    if let Some(reason) = &failure_reason {
                        let _ = writeln!(file, "failure_reason={reason}");
                    }
                }
            }

            WorkerResult {
                id: task.id,
                lane: task.lane,
                class: task.class,
                started_at,
                ended_at,
                exit_code,
                queue_delay_ms,
                lock_wait_ms,
                reused: false,
                failure_reason,
                task_digest,
                reuse_receipt_path: None,
                max_rss_kib: monitor_state.max_rss_kib(),
                max_threads: monitor_state.max_threads(),
                log_path: task_log_path.to_path_buf(),
            }
        },
    }
}

fn pipe_to_log<R: Read + Send + 'static>(
    pipe: R,
    log_handle: &Arc<Mutex<File>>,
    label: &str,
    lock_wait_tracker: &Arc<LockWaitTracker>,
) -> Result<(), String> {
    let mut reader = BufReader::new(pipe);
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|err| format!("{label} read failed: {err}"))?;
        if read == 0 {
            return Ok(());
        }
        lock_wait_tracker.observe_line(&line);

        let mut file = log_handle
            .lock()
            .map_err(|_| format!("{label} log mutex poisoned"))?;
        file.write_all(line.as_bytes())
            .map_err(|err| format!("{label} write failed: {err}"))?;
    }
}

#[derive(Default)]
struct LockWaitTracker {
    state: Mutex<LockWaitState>,
}

#[derive(Default)]
struct LockWaitState {
    active_since: Option<Instant>,
    total_wait_ms: u128,
}

impl LockWaitTracker {
    fn observe_line(&self, line: &str) {
        if let Ok(mut guard) = self.state.lock() {
            let is_lock_line = line.contains("Blocking waiting for file lock");
            match (is_lock_line, guard.active_since) {
                (true, None) => {
                    guard.active_since = Some(Instant::now());
                },
                (false, Some(started)) => {
                    guard.total_wait_ms = guard.total_wait_ms.saturating_add(
                        Instant::now()
                            .saturating_duration_since(started)
                            .as_millis(),
                    );
                    guard.active_since = None;
                },
                _ => {},
            }
        }
    }

    fn finish(&self, ended_at: Instant) -> u128 {
        if let Ok(mut guard) = self.state.lock() {
            if let Some(started) = guard.active_since.take() {
                guard.total_wait_ms = guard
                    .total_wait_ms
                    .saturating_add(ended_at.saturating_duration_since(started).as_millis());
            }
            return guard.total_wait_ms;
        }
        0
    }
}

#[derive(Default)]
struct MonitorState {
    max_rss_kib: Mutex<Option<u64>>,
    max_threads: Mutex<Option<u64>>,
}

impl MonitorState {
    fn max_rss_kib(&self) -> Option<u64> {
        self.max_rss_kib.lock().ok().and_then(|guard| *guard)
    }

    fn max_threads(&self) -> Option<u64> {
        self.max_threads.lock().ok().and_then(|guard| *guard)
    }

    fn update(&self, rss_kib: Option<u64>, threads: Option<u64>) {
        if let Some(rss) = rss_kib {
            if let Ok(mut guard) = self.max_rss_kib.lock() {
                *guard = Some(guard.map_or(rss, |current| current.max(rss)));
            }
        }
        if let Some(thread_count) = threads {
            if let Ok(mut guard) = self.max_threads.lock() {
                *guard = Some(guard.map_or(thread_count, |current| current.max(thread_count)));
            }
        }
    }
}

fn monitor_process(pid: u32, monitor_state: &MonitorState, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        let status_path = PathBuf::from(format!("/proc/{pid}/status"));
        if !status_path.exists() {
            break;
        }

        if let Ok(text) = fs::read_to_string(&status_path) {
            let mut rss_kib = None;
            let mut threads = None;

            for line in text.lines() {
                if let Some(value) = line.strip_prefix("VmRSS:") {
                    rss_kib = parse_status_number(value);
                } else if let Some(value) = line.strip_prefix("Threads:") {
                    threads = parse_status_number(value);
                }
            }

            monitor_state.update(rss_kib, threads);
        }

        thread::sleep(Duration::from_millis(250));
    }
}

fn parse_status_number(input: &str) -> Option<u64> {
    input
        .split_whitespace()
        .next()
        .and_then(|token| token.parse::<u64>().ok())
}

fn run_builtin_task(task: BuiltinTask, log: &mut File) -> i32 {
    match task {
        BuiltinTask::HostToolsCheck { required_tools } => {
            let mut missing = Vec::new();
            for tool in &required_tools {
                if find_in_path(tool).is_none() {
                    missing.push(tool.clone());
                }
            }

            if missing.is_empty() {
                let _ = writeln!(log, "status=PASS");
                0
            } else {
                let _ = writeln!(
                    log,
                    "status=FAIL\nmissing_tools={}\nmessage=Provision runner host with required toolchain",
                    missing.join(",")
                );
                let _ = writeln!(
                    log,
                    "path={}",
                    std::env::var("PATH").unwrap_or_else(|_| "<unset>".to_string())
                );
                let _ = writeln!(
                    log,
                    "cargo_home={}",
                    std::env::var("CARGO_HOME").unwrap_or_else(|_| "<unset>".to_string())
                );
                let _ = writeln!(
                    log,
                    "home={}",
                    std::env::var("HOME").unwrap_or_else(|_| "<unset>".to_string())
                );
                1
            }
        },
    }
}

fn preflight() -> Result<PreflightReport, String> {
    let hostname = detect_hostname().unwrap_or_else(|| "unknown".to_string());

    let uid = detect_uid()?;
    let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("/run/user/{uid}"));
    let dbus_session_bus_address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("unix:path={xdg_runtime_dir}/bus"));

    let bus_socket = PathBuf::from(&xdg_runtime_dir).join("bus");
    if !bus_socket.exists() {
        return Err(format!(
            "user D-Bus socket not found at {} (ensure linger and runner env export)",
            bus_socket.display()
        ));
    }

    if find_in_path("systemd-run").is_none() {
        return Err("systemd-run not found on PATH".to_string());
    }

    let preflight_status = Command::new("systemd-run")
        .args(["--user", "--quiet", "--wait", "--collect", "--", "true"])
        .env("XDG_RUNTIME_DIR", &xdg_runtime_dir)
        .env("DBUS_SESSION_BUS_ADDRESS", &dbus_session_bus_address)
        .status()
        .map_err(|err| format!("failed to execute systemd-run preflight: {err}"))?;
    if !preflight_status.success() {
        return Err("systemd-run --user preflight command failed".to_string());
    }

    let cgroup_v2_available = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    if !cgroup_v2_available {
        return Err(
            "cgroup v2 controllers not found at /sys/fs/cgroup/cgroup.controllers".to_string(),
        );
    }

    Ok(PreflightReport {
        hostname,
        expected_hostname: FAC_OVH_HOSTNAME.to_string(),
        xdg_runtime_dir,
        dbus_session_bus_address,
        user_bus_socket: bus_socket.display().to_string(),
        user_bus_socket_exists: bus_socket.exists(),
        cgroup_v2_available,
        systemd_run_user_ok: true,
    })
}

fn detect_hostname() -> Option<String> {
    let output = Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .filter(|output| output.status.success())?;

    let hostname = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
    }
}

fn detect_uid() -> Result<u32, String> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|err| format!("failed to execute id -u: {err}"))?;

    if !output.status.success() {
        return Err("id -u returned non-zero status".to_string());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    text.trim()
        .parse::<u32>()
        .map_err(|err| format!("failed to parse uid: {err}"))
}

fn run_inside_bounded_unit(args: &RunArgs, repo_root: &Path, max_parallel: usize) -> u8 {
    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("ERROR: unable to resolve current executable path: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    let command_args = vec![
        "ci".to_string(),
        "run".to_string(),
        "--profile".to_string(),
        profile_as_cli(args.profile).to_string(),
        "--heartbeat-seconds".to_string(),
        args.heartbeat_seconds.to_string(),
        "--log-mode".to_string(),
        log_mode_as_cli(args.log_mode).to_string(),
        "--artifacts-dir".to_string(),
        args.artifacts_dir.display().to_string(),
        "--max-parallel".to_string(),
        max_parallel.to_string(),
        "--heavy-lane-tokens".to_string(),
        args.heavy_lane_tokens.to_string(),
        "--reuse-mode".to_string(),
        reuse_mode_as_cli(args.reuse_mode).to_string(),
        "--reuse-store".to_string(),
        args.reuse_store.display().to_string(),
        "--countermetrics-mode".to_string(),
        countermetrics_mode_as_cli(args.countermetrics_mode).to_string(),
        "--trend-window-runs".to_string(),
        args.trend_window_runs.to_string(),
        "--trend-fail-count".to_string(),
        args.trend_fail_count.to_string(),
        "--bounded-timeout-seconds".to_string(),
        args.bounded_timeout_seconds.to_string(),
        "--bounded-kill-after-seconds".to_string(),
        args.bounded_kill_after_seconds.to_string(),
        "--bounded-memory-max".to_string(),
        args.bounded_memory_max.clone(),
        "--bounded-pids-max".to_string(),
        args.bounded_pids_max.to_string(),
        "--bounded-cpu-quota".to_string(),
        args.bounded_cpu_quota.clone(),
    ];

    let unit = format!(
        "apm2-ci-suite-{}-{}",
        std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_string()),
        std::process::id()
    );
    let bounded_entry_token = uuid::Uuid::new_v4().simple().to_string();

    println!("INFO: Starting bounded command in transient user unit: {unit}");

    let mut cmd = Command::new("systemd-run");
    let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            detect_uid().map_or_else(
                |_| "/run/user/1000".to_string(),
                |uid| format!("/run/user/{uid}"),
            )
        });
    let dbus_session_bus_address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("unix:path={xdg_runtime_dir}/bus"));

    // systemd-run --user connects to the user bus using *its own* environment.
    // Some CI runners sanitize service-level env vars before executing jobs,
    // so we always provide these explicitly (preflight already does this).
    cmd.env("XDG_RUNTIME_DIR", &xdg_runtime_dir)
        .env("DBUS_SESSION_BUS_ADDRESS", &dbus_session_bus_address);

    cmd.arg("--user")
        .arg("--pipe")
        .arg("--quiet")
        .arg("--wait")
        .arg("--collect")
        .arg("--working-directory")
        .arg(repo_root)
        .arg("--unit")
        .arg(&unit)
        .arg("--property")
        .arg("MemoryAccounting=yes")
        .arg("--property")
        .arg("CPUAccounting=yes")
        .arg("--property")
        .arg("TasksAccounting=yes")
        .arg("--property")
        .arg(format!("MemoryMax={}", args.bounded_memory_max))
        .arg("--property")
        .arg(format!("TasksMax={}", args.bounded_pids_max))
        .arg("--property")
        .arg(format!("CPUQuota={}", args.bounded_cpu_quota))
        .arg("--property")
        .arg(format!("RuntimeMaxSec={}s", args.bounded_timeout_seconds))
        .arg("--property")
        .arg(format!(
            "TimeoutStopSec={}s",
            args.bounded_kill_after_seconds
        ))
        .arg("--property")
        .arg("KillSignal=SIGTERM")
        .arg("--property")
        .arg("FinalKillSignal=SIGKILL")
        .arg("--property")
        .arg("SendSIGKILL=yes")
        .arg("--property")
        .arg("KillMode=control-group")
        .arg("--setenv")
        .arg(format!("XDG_RUNTIME_DIR={xdg_runtime_dir}"))
        .arg("--setenv")
        .arg(format!(
            "DBUS_SESSION_BUS_ADDRESS={dbus_session_bus_address}"
        ))
        .arg("--setenv")
        .arg(format!("{BOUNDED_ENTRY_TOKEN_ENV}={bounded_entry_token}"));

    // Fail-closed runner environments can vary in whether cargo-installed tools
    // are discoverable on PATH within transient systemd user units.
    // We explicitly prepend common locations:
    // - `$CARGO_HOME/bin`
    // - `$HOME/.cargo/bin`
    // - `$HOME/.install-action/bin` (used by some GitHub Actions installers)
    let home = std::env::var("HOME").ok().filter(|value| !value.is_empty());
    let cargo_home = std::env::var("CARGO_HOME")
        .ok()
        .filter(|value| !value.is_empty());
    let mut prepend = Vec::new();
    if let Some(cargo_home) = &cargo_home {
        let candidate = format!("{cargo_home}/bin");
        if Path::new(&candidate).is_dir() {
            prepend.push(candidate);
        }
    }
    if let Some(home) = &home {
        let cargo_bin = format!("{home}/.cargo/bin");
        if Path::new(&cargo_bin).is_dir() {
            prepend.push(cargo_bin);
        }
        let install_action_bin = format!("{home}/.install-action/bin");
        if Path::new(&install_action_bin).is_dir() {
            prepend.push(install_action_bin);
        }
    }

    let path = std::env::var("PATH").unwrap_or_default();
    let mut segments = Vec::new();
    let mut seen = HashSet::new();
    for candidate in prepend {
        if seen.insert(candidate.clone()) {
            segments.push(candidate);
        }
    }
    for segment in path.split(':').filter(|value| !value.is_empty()) {
        if seen.insert(segment.to_string()) {
            segments.push(segment.to_string());
        }
    }
    let augmented_path = segments.join(":");
    if !augmented_path.is_empty() {
        cmd.arg("--setenv").arg(format!("PATH={augmented_path}"));
    }

    for key in [
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_EVENT_NAME",
        "CARGO_TERM_COLOR",
        "CARGO_INCREMENTAL",
        "RUSTFLAGS",
        "RUST_BACKTRACE",
    ] {
        if let Ok(value) = std::env::var(key) {
            cmd.arg("--setenv").arg(format!("{key}={value}"));
        }
    }

    cmd.arg("--")
        .arg(&current_exe)
        .args(command_args.iter().map(String::as_str));

    let status = match cmd.status() {
        Ok(status) => status,
        Err(err) => {
            eprintln!("ERROR: failed to invoke systemd-run: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    if status.success() {
        exit_codes::SUCCESS
    } else {
        eprintln!(
            "ERROR: bounded command failed with status {}",
            status.code().unwrap_or(1)
        );
        exit_codes::GENERIC_ERROR
    }
}

const fn profile_as_cli(profile: CiProfileArg) -> &'static str {
    match profile {
        CiProfileArg::GithubPrFast => "github-pr-fast",
        CiProfileArg::GithubDeep => "github-deep",
        CiProfileArg::GithubSlowLane => "github-slow-lane",
        CiProfileArg::LocalFull => "local-full",
    }
}

const fn log_mode_as_cli(mode: CiLogModeArg) -> &'static str {
    match mode {
        CiLogModeArg::Dual => "dual",
        CiLogModeArg::StructuredOnly => "structured-only",
    }
}

const fn reuse_mode_as_cli(mode: CiReuseModeArg) -> &'static str {
    match mode {
        CiReuseModeArg::Off => "off",
        CiReuseModeArg::Strict => "strict",
    }
}

const fn countermetrics_mode_as_cli(mode: CiCountermetricsModeArg) -> &'static str {
    match mode {
        CiCountermetricsModeArg::Off => "off",
        CiCountermetricsModeArg::Soft => "soft",
        CiCountermetricsModeArg::Hard => "hard",
    }
}

fn resolve_repo_root() -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to execute git rev-parse --show-toplevel: {err}"))?;

    if !output.status.success() {
        return std::env::current_dir().map_err(|err| format!("failed to resolve cwd: {err}"));
    }

    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return Err("git rev-parse returned empty repository root".to_string());
    }

    Ok(PathBuf::from(root))
}

fn build_plan(profile: CiProfileArg, repo_root: &Path) -> Plan {
    let mut tasks = Vec::new();

    let script = |relative: &str| -> String { repo_root.join(relative).display().to_string() };
    if !matches!(profile, CiProfileArg::GithubSlowLane) {
        let static_guardrails = vec![
            ("test_safety_guard", "scripts/ci/test_safety_guard.sh"),
            ("legacy_ipc_guard", "scripts/ci/legacy_ipc_guard.sh"),
            ("evidence_refs_lint", "scripts/ci/evidence_refs_lint.sh"),
            ("test_refs_lint", "scripts/ci/test_refs_lint.sh"),
            ("proto_enum_drift", "scripts/ci/proto_enum_drift.sh"),
            ("review_artifact_lint", "scripts/ci/review_artifact_lint.sh"),
            (
                "status_write_cmd_lint",
                "scripts/lint/no_direct_status_write_commands.sh",
            ),
            (
                "safety_proof_coverage",
                "scripts/ci/safety_proof_coverage.sh",
            ),
        ];

        for (id, relative_path) in static_guardrails {
            tasks.push(TaskSpec {
                id: id.to_string(),
                lane: "static_guardrails".to_string(),
                class: TaskClass::CheapParallel,
                deps: vec!["bootstrap".to_string()],
                declared_inputs: vec![relative_path.to_string()],
                kind: TaskKind::Command(CommandSpec {
                    program: script(relative_path),
                    args: Vec::new(),
                    env: BTreeMap::new(),
                }),
            });
        }

        tasks.push(cargo_task(
            "rustfmt",
            "format",
            vec!["fmt", "--all", "--check"],
            vec!["bootstrap"],
        ));

        tasks.push(TaskSpec {
            id: "workspace_integrity_snapshot".to_string(),
            lane: "tests".to_string(),
            class: TaskClass::CheapParallel,
            deps: vec!["bootstrap".to_string()],
            declared_inputs: vec!["scripts/ci/workspace_integrity_guard.sh".to_string()],
            kind: TaskKind::Command(CommandSpec {
                program: script("scripts/ci/workspace_integrity_guard.sh"),
                args: vec![
                    "snapshot".to_string(),
                    "--snapshot-file".to_string(),
                    "target/ci/workspace_integrity.snapshot.tsv".to_string(),
                ],
                env: BTreeMap::new(),
            }),
        });

        tasks.push(cargo_task(
            "bounded_test_runner",
            "tests",
            vec![
                "nextest",
                "run",
                "--workspace",
                "--all-features",
                "--config-file",
                ".config/nextest.toml",
                "--profile",
                "ci",
            ],
            vec!["workspace_integrity_snapshot", "test_safety_guard"],
        ));

        tasks.push(TaskSpec {
            id: "workspace_integrity_guard".to_string(),
            lane: "tests".to_string(),
            class: TaskClass::CheapParallel,
            deps: vec!["bounded_test_runner".to_string()],
            declared_inputs: vec!["scripts/ci/workspace_integrity_guard.sh".to_string()],
            kind: TaskKind::Command(CommandSpec {
                program: script("scripts/ci/workspace_integrity_guard.sh"),
                args: vec![
                    "verify".to_string(),
                    "--snapshot-file".to_string(),
                    "target/ci/workspace_integrity.snapshot.tsv".to_string(),
                ],
                env: BTreeMap::new(),
            }),
        });

        tasks.push(TaskSpec {
            id: "guardrail_fixtures".to_string(),
            lane: "fixtures".to_string(),
            class: TaskClass::CheapParallel,
            deps: vec!["bootstrap".to_string(), "test_safety_guard".to_string()],
            declared_inputs: vec!["scripts/ci/test_guardrail_fixtures.sh".to_string()],
            kind: TaskKind::Command(CommandSpec {
                program: script("scripts/ci/test_guardrail_fixtures.sh"),
                args: Vec::new(),
                env: BTreeMap::new(),
            }),
        });
    }

    if matches!(profile, CiProfileArg::GithubDeep | CiProfileArg::LocalFull) {
        tasks.push(cargo_task(
            "proto_verify",
            "verify",
            vec!["build", "-p", "apm2-daemon"],
            vec!["bootstrap"],
        ));

        tasks.push(TaskSpec {
            id: "proto_verify_generated".to_string(),
            lane: "verify".to_string(),
            class: TaskClass::CheapParallel,
            deps: vec!["proto_verify".to_string()],
            declared_inputs: vec!["crates/apm2-daemon/src/protocol/apm2.daemon.v1.rs".to_string()],
            kind: TaskKind::Command(CommandSpec {
                program: "git".to_string(),
                args: vec![
                    "diff".to_string(),
                    "--exit-code".to_string(),
                    "crates/apm2-daemon/src/protocol/apm2.daemon.v1.rs".to_string(),
                ],
                env: BTreeMap::new(),
            }),
        });

        tasks.push(cargo_task(
            "clippy",
            "lint",
            vec![
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
            vec!["bootstrap"],
        ));

        let mut doc_env = BTreeMap::new();
        doc_env.insert("RUSTDOCFLAGS".to_string(), "-D warnings".to_string());
        tasks.push(TaskSpec {
            id: "doc".to_string(),
            lane: "docs".to_string(),
            class: TaskClass::CargoHeavy,
            deps: vec!["bootstrap".to_string()],
            declared_inputs: Vec::new(),
            kind: TaskKind::Command(CommandSpec {
                program: "cargo".to_string(),
                args: vec![
                    "doc".to_string(),
                    "--workspace".to_string(),
                    "--no-deps".to_string(),
                    "--all-features".to_string(),
                ],
                env: doc_env,
            }),
        });

        tasks.push(cargo_task(
            "bounded_doctests",
            "docs",
            vec!["test", "--doc", "--workspace", "--all-features"],
            vec!["bootstrap", "test_safety_guard"],
        ));

        tasks.push(cargo_task(
            "test_vectors",
            "tests",
            vec![
                "test",
                "--package",
                "apm2-core",
                "--features",
                "test_vectors",
                "canonicalization",
            ],
            vec!["bootstrap", "test_safety_guard"],
        ));

        tasks.push(TaskSpec {
            id: "msrv_check".to_string(),
            lane: "verify".to_string(),
            class: TaskClass::CargoHeavy,
            deps: vec!["bootstrap".to_string()],
            declared_inputs: Vec::new(),
            kind: TaskKind::Command(CommandSpec {
                program: "cargo".to_string(),
                args: vec![
                    "+1.85".to_string(),
                    "check".to_string(),
                    "--workspace".to_string(),
                    "--all-features".to_string(),
                ],
                env: BTreeMap::new(),
            }),
        });

        tasks.push(TaskSpec {
            id: "cargo_deny".to_string(),
            lane: "security".to_string(),
            class: TaskClass::CargoHeavy,
            deps: vec!["bootstrap".to_string()],
            declared_inputs: Vec::new(),
            kind: TaskKind::Command(CommandSpec {
                program: "cargo".to_string(),
                args: vec!["deny".to_string(), "check".to_string(), "all".to_string()],
                env: BTreeMap::new(),
            }),
        });

        tasks.push(TaskSpec {
            id: "cargo_audit".to_string(),
            lane: "security".to_string(),
            class: TaskClass::CargoHeavy,
            deps: vec!["bootstrap".to_string()],
            declared_inputs: Vec::new(),
            kind: TaskKind::Command(CommandSpec {
                program: "cargo".to_string(),
                args: vec![
                    "audit".to_string(),
                    "--ignore".to_string(),
                    "RUSTSEC-2023-0089".to_string(),
                ],
                env: BTreeMap::new(),
            }),
        });

        tasks.push(TaskSpec {
            id: "coverage".to_string(),
            lane: "coverage".to_string(),
            class: TaskClass::CargoHeavy,
            deps: vec!["bootstrap".to_string(), "test_safety_guard".to_string()],
            declared_inputs: Vec::new(),
            kind: TaskKind::Command(CommandSpec {
                program: "cargo".to_string(),
                args: vec![
                    "llvm-cov".to_string(),
                    "--workspace".to_string(),
                    "--all-features".to_string(),
                    "--lcov".to_string(),
                    "--output-path".to_string(),
                    "target/ci/lcov.info".to_string(),
                ],
                env: BTreeMap::new(),
            }),
        });
    }

    if matches!(
        profile,
        CiProfileArg::GithubSlowLane | CiProfileArg::LocalFull
    ) {
        tasks.push(cargo_task(
            "release_build",
            "release",
            vec!["build", "--workspace", "--release"],
            vec!["bootstrap"],
        ));
    }

    let required_tools = required_tools_for_plan(&tasks);
    tasks.insert(
        0,
        TaskSpec {
            id: "bootstrap".to_string(),
            lane: "bootstrap".to_string(),
            class: TaskClass::CheapParallel,
            deps: Vec::new(),
            declared_inputs: Vec::new(),
            kind: TaskKind::Builtin(BuiltinTask::HostToolsCheck { required_tools }),
        },
    );

    Plan { profile, tasks }
}

fn required_tools_for_plan(tasks: &[TaskSpec]) -> Vec<String> {
    let mut required = BTreeSet::new();

    // Baseline host toolchain required for *all* profiles.
    for tool in [
        "cargo",
        "rustc",
        "git",
        "protoc",
        "rg",
        "jq",
        "timeout",
        "systemd-run",
        "rustup",
    ] {
        required.insert(tool.to_string());
    }

    // Infer required cargo plugin binaries from the plan surface so we don't
    // fail bootstrap due to tools that won't be invoked in the selected plan.
    for task in tasks {
        let TaskKind::Command(spec) = &task.kind else {
            continue;
        };
        if spec.program != "cargo" {
            continue;
        }

        let mut args = spec.args.iter().map(String::as_str);
        let Some(mut subcommand) = args.next() else {
            continue;
        };
        if subcommand.starts_with('+') {
            subcommand = match args.next() {
                Some(value) => value,
                None => continue,
            };
        }

        match subcommand {
            "nextest" => {
                required.insert("cargo-nextest".to_string());
            },
            "deny" => {
                required.insert("cargo-deny".to_string());
            },
            "audit" => {
                required.insert("cargo-audit".to_string());
            },
            "llvm-cov" => {
                required.insert("cargo-llvm-cov".to_string());
            },
            _ => {},
        }
    }

    required.into_iter().collect()
}

fn cargo_task(id: &str, lane: &str, args: Vec<&str>, deps: Vec<&str>) -> TaskSpec {
    TaskSpec {
        id: id.to_string(),
        lane: lane.to_string(),
        class: TaskClass::CargoHeavy,
        deps: deps.into_iter().map(str::to_string).collect::<Vec<_>>(),
        declared_inputs: Vec::new(),
        kind: TaskKind::Command(CommandSpec {
            program: "cargo".to_string(),
            args: args.into_iter().map(str::to_string).collect::<Vec<_>>(),
            env: BTreeMap::new(),
        }),
    }
}

fn validate_plan(plan: &Plan) -> Result<(), String> {
    let ids = plan
        .tasks
        .iter()
        .map(|task| task.id.clone())
        .collect::<HashSet<_>>();

    for task in &plan.tasks {
        for dep in &task.deps {
            if !ids.contains(dep) {
                return Err(format!(
                    "task '{}' depends on unknown task '{}'; profile={:?}",
                    task.id, dep, plan.profile
                ));
            }
        }
        if task_requires_test_safety_guard(task)
            && !task.deps.iter().any(|dep| dep == "test_safety_guard")
        {
            return Err(format!(
                "task '{}' must depend on 'test_safety_guard' (fail-closed test safety contract)",
                task.id
            ));
        }
    }

    Ok(())
}

fn task_requires_test_safety_guard(task: &TaskSpec) -> bool {
    matches!(
        task.id.as_str(),
        "bounded_test_runner"
            | "bounded_doctests"
            | "test_vectors"
            | "coverage"
            | "guardrail_fixtures"
    )
}

fn clone_task(task: &TaskSpec) -> TaskSpec {
    TaskSpec {
        id: task.id.clone(),
        lane: task.lane.clone(),
        class: task.class,
        deps: task.deps.clone(),
        declared_inputs: task.declared_inputs.clone(),
        kind: match &task.kind {
            TaskKind::Builtin(builtin) => TaskKind::Builtin(builtin.clone()),
            TaskKind::Command(spec) => TaskKind::Command(CommandSpec {
                program: spec.program.clone(),
                args: spec.args.clone(),
                env: spec.env.clone(),
            }),
        },
    }
}

fn write_event(
    events_file: &Arc<Mutex<File>>,
    event: &str,
    fields: serde_json::Value,
) -> Result<(), String> {
    let envelope = EventEnvelope {
        ts_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("clock error: {err}"))?
            .as_millis(),
        event: event.to_string(),
        fields,
    };

    let mut file = events_file
        .lock()
        .map_err(|_| "events file mutex poisoned".to_string())?;
    let mut line =
        serde_json::to_vec(&envelope).map_err(|err| format!("failed to serialize event: {err}"))?;
    line.push(b'\n');
    file.write_all(&line)
        .map_err(|err| format!("failed to write event: {err}"))
}

fn format_command_for_display(spec: &CommandSpec) -> String {
    let mut parts = Vec::with_capacity(1 + spec.args.len());
    parts.push(shell_quote(spec.program.as_str()));
    for arg in &spec.args {
        parts.push(shell_quote(arg));
    }
    parts.join(" ")
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_.:/%+=,@".contains(ch))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for segment in std::env::split_paths(&path_var) {
        let candidate = segment.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn detect_bounded_entry_context() -> Result<bool, String> {
    match std::env::var(BOUNDED_ENTRY_TOKEN_ENV) {
        Ok(token) => {
            if token.len() < 16 || !token.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(
                    "bounded entry token is malformed (expected >=16 hex chars)".to_string()
                );
            }
            let cgroup_path = current_cgroup_path()
                .ok_or_else(|| "unable to resolve current cgroup path".to_string())?;
            if !cgroup_path.contains("apm2-ci-suite-") {
                return Err(format!(
                    "{BOUNDED_ENTRY_TOKEN_ENV} present outside bounded unit cgroup ({cgroup_path})"
                ));
            }
            Ok(true)
        },
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(err) => Err(format!("failed to read {BOUNDED_ENTRY_TOKEN_ENV}: {err}")),
    }
}

fn resolve_git_head(repo_root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("failed to execute git rev-parse HEAD: {err}"))?;
    if !output.status.success() {
        return Err("git rev-parse HEAD returned non-zero status".to_string());
    }
    let head = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if head.is_empty() {
        return Err("git rev-parse HEAD returned empty output".to_string());
    }
    Ok(head)
}

fn is_tracked_tree_clean(repo_root: &Path) -> Result<bool, String> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map_err(|err| format!("failed to execute git status --porcelain: {err}"))?;
    if !output.status.success() {
        return Err("git status --porcelain returned non-zero status".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn command_stdout(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| format!("failed to execute {cmd}: {err}"))?;
    if !output.status.success() {
        return Err(format!("{cmd} returned non-zero status"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn compute_toolchain_fingerprint() -> Result<String, String> {
    let rustc = command_stdout("rustc", &["-Vv"])?;
    let cargo = command_stdout("cargo", &["-V"])?;
    let joined = format!("rustc={rustc}\ncargo={cargo}");
    Ok(blake3::hash(joined.as_bytes()).to_hex().to_string())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create parent {}: {err}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("failed to resolve filename for {}", path.display()))?;
    let temp_path = parent.join(format!(".{file_name}.tmp-{}", uuid::Uuid::new_v4()));
    {
        let mut file = File::create(&temp_path)
            .map_err(|err| format!("failed to create {}: {err}", temp_path.display()))?;
        file.write_all(bytes)
            .map_err(|err| format!("failed to write {}: {err}", temp_path.display()))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync {}: {err}", temp_path.display()))?;
    }
    fs::rename(&temp_path, path).map_err(|err| {
        format!(
            "failed to rename {} to {}: {err}",
            temp_path.display(),
            path.display()
        )
    })
}

fn now_unix_ms() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock error: {err}"))
        .map(|dur| dur.as_millis())
}

fn hash_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn relative_display(path: &Path, root: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |stripped| stripped.display().to_string(),
    )
}

fn declared_or_detected_input_files(task: &TaskSpec, repo_root: &Path) -> Vec<PathBuf> {
    let mut files = BTreeSet::new();
    for declared in &task.declared_inputs {
        let path = repo_root.join(declared);
        if path.is_file() {
            files.insert(path);
        }
    }

    if let TaskKind::Command(spec) = &task.kind {
        let program_path = PathBuf::from(&spec.program);
        if program_path.is_absolute()
            && program_path.is_file()
            && program_path.starts_with(repo_root)
        {
            files.insert(program_path);
        }
        for arg in &spec.args {
            let candidate = repo_root.join(arg);
            if candidate.is_file() {
                files.insert(candidate);
            }
        }
    }

    let cargo_lock = repo_root.join("Cargo.lock");
    if cargo_lock.is_file() {
        files.insert(cargo_lock);
    }
    let nextest_config = repo_root.join(".config/nextest.toml");
    if nextest_config.is_file() {
        files.insert(nextest_config);
    }

    files.into_iter().collect::<Vec<_>>()
}

fn task_env_fingerprint(spec: &CommandSpec) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for (key, value) in &spec.env {
        env.insert(
            format!("task:{key}"),
            blake3::hash(value.as_bytes()).to_hex().to_string(),
        );
    }
    for key in [
        "PATH",
        "RUSTFLAGS",
        "CARGO_INCREMENTAL",
        "RUSTDOCFLAGS",
        "CARGO_HOME",
        "RUSTUP_HOME",
    ] {
        if let Ok(value) = std::env::var(key) {
            env.insert(
                format!("process:{key}"),
                blake3::hash(value.as_bytes()).to_hex().to_string(),
            );
        }
    }
    env
}

fn compute_task_digest(
    run_ctx: &RunContext,
    profile: CiProfileArg,
    task: &TaskSpec,
    completed: &HashMap<String, TaskOutcome>,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct TaskDigestPayload {
        schema: &'static str,
        schema_version: &'static str,
        profile: CiProfileArg,
        task_id: String,
        task_class: TaskClass,
        lane: String,
        program: String,
        args: Vec<String>,
        env_fingerprint: BTreeMap<String, String>,
        input_digests: BTreeMap<String, String>,
        dependency_task_digests: BTreeMap<String, String>,
        toolchain_fingerprint: String,
        git_head: String,
        tracked_clean: bool,
    }

    let (program, args, env_fingerprint) = match &task.kind {
        TaskKind::Builtin(builtin) => match builtin {
            BuiltinTask::HostToolsCheck { required_tools } => (
                "builtin::host_tools_check".to_string(),
                required_tools.clone(),
                BTreeMap::new(),
            ),
        },
        TaskKind::Command(spec) => (
            spec.program.clone(),
            spec.args.clone(),
            task_env_fingerprint(spec),
        ),
    };

    let mut input_digests = BTreeMap::new();
    for file in declared_or_detected_input_files(task, &run_ctx.repo_root) {
        input_digests.insert(
            relative_display(&file, &run_ctx.repo_root),
            hash_file(&file)?,
        );
    }

    let mut dependency_task_digests = BTreeMap::new();
    for dep in &task.deps {
        let dep_digest = completed
            .get(dep)
            .and_then(|outcome| outcome.summary.task_digest.clone())
            .ok_or_else(|| format!("dependency digest missing for task '{dep}'"))?;
        dependency_task_digests.insert(dep.clone(), dep_digest);
    }

    let payload = TaskDigestPayload {
        schema: REUSE_RECEIPT_SCHEMA,
        schema_version: REUSE_RECEIPT_SCHEMA_VERSION,
        profile,
        task_id: task.id.clone(),
        task_class: task.class,
        lane: task.lane.clone(),
        program,
        args,
        env_fingerprint,
        input_digests,
        dependency_task_digests,
        toolchain_fingerprint: run_ctx.toolchain_fingerprint.clone(),
        git_head: run_ctx.git_head.clone(),
        tracked_clean: run_ctx.tracked_clean,
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|err| format!("failed to serialize task digest payload: {err}"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

#[derive(Debug)]
struct LoadedReuseReceipt {
    path: PathBuf,
}

fn reuse_receipt_path(
    run_ctx: &RunContext,
    profile: CiProfileArg,
    task_id: &str,
    digest: &str,
) -> PathBuf {
    run_ctx
        .reuse_store
        .join(profile_as_cli(profile))
        .join(task_id)
        .join(format!("{digest}.json"))
}

fn load_reuse_receipt(
    run_ctx: &RunContext,
    profile: CiProfileArg,
    task_id: &str,
    task_digest: &str,
) -> Result<Option<LoadedReuseReceipt>, String> {
    if !run_ctx.tracked_clean {
        return Ok(None);
    }

    let path = reuse_receipt_path(run_ctx, profile, task_id, task_digest);
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&path)
        .map_err(|err| format!("failed to read reuse receipt {}: {err}", path.display()))?;
    let receipt: TaskReuseReceiptV2 = serde_json::from_slice(&bytes)
        .map_err(|err| format!("failed to parse reuse receipt {}: {err}", path.display()))?;

    if receipt.schema != REUSE_RECEIPT_SCHEMA
        || receipt.schema_version != REUSE_RECEIPT_SCHEMA_VERSION
        || receipt.task_id != task_id
        || receipt.profile != profile
        || receipt.task_digest != task_digest
        || receipt.state != TaskState::Pass
        || receipt.exit_code != 0
        || receipt.toolchain_fingerprint != run_ctx.toolchain_fingerprint
        || receipt.git_head != run_ctx.git_head
        || !receipt.tracked_clean
    {
        return Ok(None);
    }

    Ok(Some(LoadedReuseReceipt { path }))
}

fn store_reuse_receipt(
    run_ctx: &RunContext,
    profile: CiProfileArg,
    summary: &TaskSummary,
) -> Result<PathBuf, String> {
    let digest = summary
        .task_digest
        .as_ref()
        .ok_or_else(|| format!("task '{}' missing task_digest", summary.id))?;
    let receipt_path = reuse_receipt_path(run_ctx, profile, &summary.id, digest);
    let log_digest = hash_file(Path::new(&summary.log_path))?;
    let receipt = TaskReuseReceiptV2 {
        schema: REUSE_RECEIPT_SCHEMA.to_string(),
        schema_version: REUSE_RECEIPT_SCHEMA_VERSION.to_string(),
        run_id: run_ctx.run_id.clone(),
        profile,
        task_id: summary.id.clone(),
        task_class: summary.class,
        task_digest: digest.clone(),
        state: summary.state,
        exit_code: summary.exit_code,
        log_digest,
        toolchain_fingerprint: run_ctx.toolchain_fingerprint.clone(),
        git_head: run_ctx.git_head.clone(),
        tracked_clean: run_ctx.tracked_clean,
        created_unix_ms: now_unix_ms()?,
    };
    let bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|err| format!("failed to serialize reuse receipt: {err}"))?;
    atomic_write(&receipt_path, &bytes)?;
    Ok(receipt_path)
}

fn append_reuse_event(
    reuse_events_file: &Arc<Mutex<File>>,
    event: &TaskReuseEventV2,
) -> Result<(), String> {
    let mut file = reuse_events_file
        .lock()
        .map_err(|_| "reuse events file mutex poisoned".to_string())?;
    let mut line = serde_json::to_vec(&event)
        .map_err(|err| format!("failed to serialize reuse event: {err}"))?;
    line.push(b'\n');
    file.write_all(&line)
        .map_err(|err| format!("failed to append reuse event: {err}"))
}

fn ratio_from_counts(numerator: usize, denominator: usize) -> f64 {
    let numerator = u32::try_from(numerator).unwrap_or(u32::MAX);
    let denominator = u32::try_from(denominator).unwrap_or(u32::MAX);
    f64::from(numerator) / f64::from(denominator)
}

fn compute_artifact_completeness_ratio(
    run_ctx: &RunContext,
    tasks: &[TaskSummary],
    include_final_outputs: bool,
) -> f64 {
    let mut expected = vec![
        run_ctx.run_dir.join("manifest.json"),
        run_ctx.manifest_v2_path.clone(),
        run_ctx.events_path.clone(),
        run_ctx.reuse_events_path.clone(),
    ];
    if include_final_outputs {
        expected.push(run_ctx.run_dir.join("summary.json"));
        expected.push(run_ctx.summary_v2_path.clone());
        expected.push(run_ctx.countermetrics_v2_path.clone());
    }
    for task in tasks {
        expected.push(PathBuf::from(&task.log_path));
    }
    let present = expected.iter().filter(|path| path.exists()).count();
    if expected.is_empty() {
        return 1.0;
    }
    ratio_from_counts(present, expected.len())
}

fn percentile_95(values: &[u128]) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = sorted
        .len()
        .saturating_mul(95)
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[idx]
}

fn evaluate_countermetrics(
    run_ctx: &RunContext,
    tasks: &[TaskSummary],
    artifact_completeness_ratio: f64,
) -> CountermetricsV2 {
    let heavy_tasks = tasks
        .iter()
        .filter(|task| task.class == TaskClass::CargoHeavy)
        .collect::<Vec<_>>();
    let heavy_duration_ms = heavy_tasks
        .iter()
        .map(|task| task.duration_ms)
        .sum::<u128>();
    let heavy_lock_wait_ms = heavy_tasks
        .iter()
        .map(|task| task.lock_wait_ms)
        .sum::<u128>();
    let lock_wait_ratio = if heavy_duration_ms == 0 {
        0.0
    } else {
        ratio_from_counts(
            usize::try_from(heavy_lock_wait_ms).unwrap_or(usize::MAX),
            usize::try_from(heavy_duration_ms).unwrap_or(usize::MAX),
        )
    };
    let queue_delay_p95_ms = percentile_95(
        &tasks
            .iter()
            .map(|task| task.queue_delay_ms)
            .collect::<Vec<_>>(),
    );

    let lock_wait_warn_breach = lock_wait_ratio > COUNTERMETRIC_LOCK_WAIT_WARN;
    let lock_wait_fail_breach = lock_wait_ratio > COUNTERMETRIC_LOCK_WAIT_FAIL;
    let queue_delay_warn_breach = queue_delay_p95_ms > COUNTERMETRIC_QUEUE_DELAY_WARN_MS;
    let queue_delay_fail_breach = queue_delay_p95_ms > COUNTERMETRIC_QUEUE_DELAY_FAIL_MS;
    let artifact_completeness_fail_breach = artifact_completeness_ratio < 1.0;

    CountermetricsV2 {
        schema: COUNTERMETRICS_SCHEMA,
        schema_version: COUNTERMETRICS_SCHEMA_VERSION,
        lock_wait_ratio,
        queue_delay_p95_ms,
        artifact_completeness_ratio,
        warmup_active: true,
        trend_window_runs: run_ctx.trend_window_runs,
        trend_fail_count: run_ctx.trend_fail_count,
        trend_breach_count: 0,
        history_runs_considered: 0,
        lock_wait_warn_breach,
        lock_wait_fail_breach,
        queue_delay_warn_breach,
        queue_delay_fail_breach,
        artifact_completeness_fail_breach,
        gate_failed: artifact_completeness_fail_breach,
    }
}

fn countermetric_history_path(run_ctx: &RunContext) -> PathBuf {
    run_ctx
        .artifacts_root
        .join("countermetrics-history.v2.ndjson")
}

fn countermetric_history_lock_path(run_ctx: &RunContext) -> PathBuf {
    run_ctx
        .artifacts_root
        .join("countermetrics-history.v2.lock")
}

fn persist_countermetric_history(
    run_ctx: &RunContext,
    countermetrics: &mut CountermetricsV2,
    profile: CiProfileArg,
) -> Result<(), String> {
    let lock_path = countermetric_history_lock_path(run_ctx);
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open history lock {}: {err}", lock_path.display()))?;
    lock_file
        .lock_exclusive()
        .map_err(|err| format!("failed to lock history {}: {err}", lock_path.display()))?;

    let persist_result = persist_countermetric_history_locked(run_ctx, countermetrics, profile);
    drop(lock_file);
    persist_result
}

fn persist_countermetric_history_locked(
    run_ctx: &RunContext,
    countermetrics: &mut CountermetricsV2,
    profile: CiProfileArg,
) -> Result<(), String> {
    let history_path = countermetric_history_path(run_ctx);
    let mut history_lines = Vec::new();
    let mut records = Vec::new();

    if history_path.exists() {
        let file = File::open(&history_path)
            .map_err(|err| format!("failed to open history {}: {err}", history_path.display()))?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line.map_err(|err| format!("failed to read history line: {err}"))?;
            if line.trim().is_empty() {
                continue;
            }
            let record: CountermetricsHistoryRecordV2 = serde_json::from_str(&line)
                .map_err(|err| format!("failed to parse countermetric history record: {err}"))?;
            history_lines.push(line);
            if record.profile == profile {
                records.push(record);
            }
        }
    }

    let breach = countermetrics.lock_wait_fail_breach || countermetrics.queue_delay_fail_breach;
    countermetrics.history_runs_considered = records.len();
    match run_ctx.countermetrics_mode {
        CiCountermetricsModeArg::Off => {
            countermetrics.warmup_active = true;
        },
        CiCountermetricsModeArg::Hard => {
            countermetrics.warmup_active = false;
            if breach {
                countermetrics.gate_failed = true;
            }
        },
        CiCountermetricsModeArg::Soft => {
            if records.len() < run_ctx.trend_window_runs {
                countermetrics.warmup_active = true;
            } else {
                countermetrics.warmup_active = false;
                let take_count = run_ctx.trend_window_runs.saturating_sub(1);
                let prior_breaches = records
                    .iter()
                    .rev()
                    .take(take_count)
                    .filter(|record| record.breach)
                    .count();
                let breach_count = prior_breaches + usize::from(breach);
                countermetrics.trend_breach_count = breach_count;
                if breach_count >= run_ctx.trend_fail_count {
                    countermetrics.gate_failed = true;
                }
            }
        },
    }

    let new_record = CountermetricsHistoryRecordV2 {
        schema: TREND_HISTORY_SCHEMA.to_string(),
        schema_version: TREND_HISTORY_SCHEMA_VERSION.to_string(),
        run_id: run_ctx.run_id.clone(),
        profile,
        lock_wait_ratio: countermetrics.lock_wait_ratio,
        queue_delay_p95_ms: countermetrics.queue_delay_p95_ms,
        breach,
        created_unix_ms: now_unix_ms()?,
    };
    history_lines.push(
        serde_json::to_string(&new_record)
            .map_err(|err| format!("failed to serialize history record: {err}"))?,
    );
    let joined = format!("{}\n", history_lines.join("\n"));
    atomic_write(&history_path, joined.as_bytes())
}

#[derive(Debug)]
struct BoundedCgroupCleanupGuard {
    enabled: bool,
}

impl BoundedCgroupCleanupGuard {
    const fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

impl Drop for BoundedCgroupCleanupGuard {
    fn drop(&mut self) {
        if self.enabled {
            cleanup_lingering_cgroup_processes();
        }
    }
}

fn cleanup_lingering_cgroup_processes() {
    let Some(cgroup_path) = current_cgroup_path() else {
        return;
    };
    if !cgroup_path.contains("apm2-ci-suite-") {
        return;
    }

    let cgroup_procs_path = Path::new("/sys/fs/cgroup")
        .join(cgroup_path.trim_start_matches('/'))
        .join("cgroup.procs");
    if !cgroup_procs_path.exists() {
        return;
    }

    let self_pid = std::process::id();
    let mut lingering = read_lingering_cgroup_pids(&cgroup_procs_path, self_pid);
    if lingering.is_empty() {
        return;
    }

    eprintln!("WARN: detected lingering bounded-unit processes; attempting drain: {lingering:?}");

    signal_pids("TERM", &lingering);

    let wait_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < wait_deadline {
        thread::sleep(Duration::from_millis(100));
        lingering = read_lingering_cgroup_pids(&cgroup_procs_path, self_pid);
        if lingering.is_empty() {
            eprintln!("INFO: bounded-unit process drain completed after SIGTERM");
            return;
        }
    }

    signal_pids("KILL", &lingering);
    thread::sleep(Duration::from_millis(100));
    lingering = read_lingering_cgroup_pids(&cgroup_procs_path, self_pid);

    if lingering.is_empty() {
        eprintln!("INFO: bounded-unit process drain completed after SIGKILL");
    } else {
        eprintln!("WARN: bounded-unit process drain incomplete; remaining pids: {lingering:?}");
    }
}

fn current_cgroup_path() -> Option<String> {
    let content = fs::read_to_string("/proc/self/cgroup").ok()?;
    content.lines().find_map(|line| {
        line.split_once("::")
            .map(|(_, path)| path.trim().to_string())
    })
}

fn read_lingering_cgroup_pids(cgroup_procs_path: &Path, self_pid: u32) -> Vec<u32> {
    let Ok(content) = fs::read_to_string(cgroup_procs_path) else {
        return Vec::new();
    };

    content
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|pid| *pid != self_pid)
        .collect::<Vec<_>>()
}

fn signal_pids(signal: &str, pids: &[u32]) {
    if pids.is_empty() {
        return;
    }

    let mut cmd = Command::new("kill");
    cmd.arg(format!("-{signal}"));
    for pid in pids {
        cmd.arg(pid.to_string());
    }

    if let Err(err) = cmd.status() {
        eprintln!("WARN: failed to invoke kill -{signal} for cgroup drain: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status_number() {
        assert_eq!(parse_status_number("      123 kB"), Some(123));
        assert_eq!(parse_status_number(" 9"), Some(9));
        assert_eq!(parse_status_number("n/a"), None);
    }

    #[test]
    fn test_shell_quote_plain() {
        assert_eq!(shell_quote("cargo"), "cargo");
        assert_eq!(shell_quote("--workspace"), "--workspace");
    }

    #[test]
    fn test_shell_quote_escaped() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
    }

    #[test]
    fn test_validate_plan_rejects_missing_dependency() {
        let plan = Plan {
            profile: CiProfileArg::LocalFull,
            tasks: vec![TaskSpec {
                id: "task-a".to_string(),
                lane: "x".to_string(),
                class: TaskClass::CheapParallel,
                deps: vec!["task-b".to_string()],
                declared_inputs: Vec::new(),
                kind: TaskKind::Builtin(BuiltinTask::HostToolsCheck {
                    required_tools: vec!["cargo".to_string()],
                }),
            }],
        };

        let err = validate_plan(&plan).expect_err("expected invalid plan");
        assert!(err.contains("unknown task"));
    }

    #[test]
    fn test_build_plan_has_bootstrap() {
        let plan = build_plan(CiProfileArg::GithubPrFast, Path::new("/tmp/repo"));
        assert!(plan.tasks.iter().any(|task| task.id == "bootstrap"));
    }

    #[test]
    fn test_bootstrap_required_tools_are_profile_scoped() {
        let plan = build_plan(CiProfileArg::GithubPrFast, Path::new("/tmp/repo"));
        let bootstrap = plan
            .tasks
            .iter()
            .find(|task| task.id == "bootstrap")
            .expect("expected bootstrap task");
        let TaskKind::Builtin(BuiltinTask::HostToolsCheck { required_tools }) = &bootstrap.kind
        else {
            panic!("bootstrap should be a HostToolsCheck builtin task");
        };

        assert!(
            required_tools.iter().any(|tool| tool == "cargo-nextest"),
            "github-pr-fast should require cargo-nextest"
        );
        for tool in ["cargo-deny", "cargo-audit", "cargo-llvm-cov"] {
            assert!(
                !required_tools.iter().any(|entry| entry == tool),
                "github-pr-fast should not require {tool}",
            );
        }

        let plan = build_plan(CiProfileArg::GithubDeep, Path::new("/tmp/repo"));
        let bootstrap = plan
            .tasks
            .iter()
            .find(|task| task.id == "bootstrap")
            .expect("expected bootstrap task");
        let TaskKind::Builtin(BuiltinTask::HostToolsCheck { required_tools }) = &bootstrap.kind
        else {
            panic!("bootstrap should be a HostToolsCheck builtin task");
        };
        for tool in [
            "cargo-nextest",
            "cargo-deny",
            "cargo-audit",
            "cargo-llvm-cov",
        ] {
            assert!(
                required_tools.iter().any(|entry| entry == tool),
                "github-deep should require {tool}",
            );
        }
    }

    #[test]
    fn test_build_plan_deep_excludes_release() {
        let plan = build_plan(CiProfileArg::GithubDeep, Path::new("/tmp/repo"));
        assert!(!plan.tasks.iter().any(|task| task.id == "release_build"));
    }

    #[test]
    fn test_build_plan_slow_lane_contains_release() {
        let plan = build_plan(CiProfileArg::GithubSlowLane, Path::new("/tmp/repo"));
        assert!(plan.tasks.iter().any(|task| task.id == "release_build"));
    }

    #[test]
    fn test_build_plan_slow_lane_excludes_fast_and_test_surface() {
        let plan = build_plan(CiProfileArg::GithubSlowLane, Path::new("/tmp/repo"));
        for excluded in [
            "test_safety_guard",
            "bounded_test_runner",
            "bounded_doctests",
            "test_vectors",
            "coverage",
            "guardrail_fixtures",
            "rustfmt",
        ] {
            assert!(
                !plan.tasks.iter().any(|task| task.id == excluded),
                "slow-lane profile should not include {excluded}",
            );
        }
    }

    #[test]
    fn test_test_tasks_depend_on_test_safety_guard() {
        let plan = build_plan(CiProfileArg::GithubDeep, Path::new("/tmp/repo"));
        for guarded in [
            "bounded_test_runner",
            "bounded_doctests",
            "test_vectors",
            "coverage",
            "guardrail_fixtures",
        ] {
            let task = plan
                .tasks
                .iter()
                .find(|task| task.id == guarded)
                .unwrap_or_else(|| panic!("expected task {guarded} in github-deep profile"));
            assert!(
                task.deps.iter().any(|dep| dep == "test_safety_guard"),
                "task {guarded} must depend on test_safety_guard",
            );
        }
    }
}
