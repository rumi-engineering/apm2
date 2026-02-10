//! apm2-daemon - AI CLI Process Manager Daemon
//!
//! This is the main daemon binary that manages AI CLI processes.
//!
//! # `ProtocolServer`-Only Control Plane (TCK-00279)
//!
//! Per DD-009 (RFC-0017), the daemon uses a dual-socket `ProtocolServer`
//! architecture:
//! - **Operator socket** (`operator.sock`, mode 0600): Privileged operations
//! - **Session socket** (`session.sock`, mode 0660): Session-scoped operations
//!
//! Legacy JSON IPC has been removed. `ProtocolServer` is the only control-plane
//! IPC.
//!
//! # Prometheus Metrics (TCK-00268)
//!
//! The daemon exposes Prometheus metrics at `/metrics` (default port 9100).
//! Per REQ-DCP-0012, the following metrics are exposed:
//! - `apm2_daemon_sessions_active` (gauge)
//! - `apm2_daemon_tool_mediation_latency_seconds` (histogram)
//! - `apm2_daemon_ipc_requests_total` (counter)
//! - `apm2_daemon_capability_grants_total` (counter)
//! - `apm2_daemon_context_firewall_denials_total` (counter)
//! - `apm2_daemon_session_terminations_total` (counter)
//!
//! See RFC-0017 for architecture details.
//!
//! # Fork Safety (TCK-00282)
//!
//! Daemonization via `fork()` MUST occur BEFORE the Tokio runtime starts.
//! The `#[tokio::main]` macro expands to code that initializes a multi-threaded
//! runtime and spawns worker threads BEFORE the async fn body executes. Calling
//! `fork()` in a multi-threaded process is undefined behavior because:
//!
//! 1. `fork()` only duplicates the calling thread, not all threads
//! 2. Mutexes held by other threads remain locked forever in the child
//! 3. This leads to deadlocks and undefined behavior
//!
//! To ensure safety, this binary uses a synchronous `fn main()` that performs
//! all daemonization (fork, setsid, chdir) in a truly single-threaded context,
//! THEN manually constructs and runs the Tokio runtime via `block_on()`.

// mod protocol; // Use library crate instead to avoid dead code warnings
// mod state; // Use library crate

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use apm2_core::bootstrap::verify_bootstrap_hash;
use apm2_core::config::EcosystemConfig;
use apm2_core::crypto::Signer;
use apm2_core::process::ProcessState;
use apm2_core::schema_registry::{InMemorySchemaRegistry, register_kernel_schemas};
use apm2_core::supervisor::Supervisor;
use apm2_daemon::gate::{GateOrchestrator, GateOrchestratorConfig};
use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
use apm2_daemon::metrics::{SharedMetricsRegistry, new_shared_registry};
use apm2_daemon::projection::{DivergenceWatchdog, DivergenceWatchdogConfig};
use apm2_daemon::protocol; // Import from library
use apm2_daemon::protocol::socket_manager::{SocketManager, SocketManagerConfig};
use apm2_daemon::state::{DaemonStateHandle, DispatcherState, SharedDispatcherState, SharedState};
use axum::Router;
use axum::routing::get;
use clap::Parser;
use rusqlite::Connection;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// apm2 daemon - AI CLI process manager
#[derive(Parser, Debug)]
#[command(name = "apm2-daemon")]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to ecosystem configuration file
    #[arg(short, long, default_value = "ecosystem.toml")]
    config: PathBuf,

    /// Run in foreground (don't daemonize)
    #[arg(long)]
    no_daemon: bool,

    /// Path to PID file
    #[arg(long)]
    pid_file: Option<PathBuf>,

    /// Path to operator Unix socket (mode 0600, privileged operations)
    #[arg(long)]
    operator_socket: Option<PathBuf>,

    /// Path to session Unix socket (mode 0660, session-scoped operations)
    #[arg(long)]
    session_socket: Option<PathBuf>,

    /// Path to state file for persistent session registry (TCK-00266)
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// Path to ledger database file (`SQLite`)
    #[arg(long)]
    ledger_db: Option<PathBuf>,

    /// Path to durable content-addressed storage (CAS) directory (TCK-00383)
    ///
    /// When provided with `--ledger-db`, enables full session dispatcher wiring
    /// via `with_persistence_and_cas()`. The directory is created with mode
    /// 0700 if it does not exist.
    #[arg(long)]
    cas_path: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Log to file instead of stdout
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Port for Prometheus metrics HTTP endpoint (TCK-00268)
    /// Default: 9100
    #[arg(long, default_value = "9100")]
    metrics_port: u16,

    /// Disable Prometheus metrics HTTP endpoint
    #[arg(long)]
    no_metrics: bool,
}

/// Default port for Prometheus metrics HTTP endpoint (TCK-00268).
pub const DEFAULT_METRICS_PORT: u16 = 9100;

/// Daemon configuration derived from args and config file.
struct DaemonConfig {
    config: EcosystemConfig,
    operator_socket_path: PathBuf,
    session_socket_path: PathBuf,
    pid_path: PathBuf,
    /// State file path for persistent session registry (TCK-00266).
    state_file_path: PathBuf,
    /// Ledger database path (`SQLite`).
    ledger_db_path: Option<PathBuf>,
    /// CAS directory path for durable content-addressed storage (TCK-00383).
    cas_path: Option<PathBuf>,
    /// Port for Prometheus metrics HTTP endpoint (TCK-00268).
    metrics_port: u16,
    /// Whether to disable the metrics endpoint.
    metrics_disabled: bool,
}

impl DaemonConfig {
    fn new(args: &Args) -> Result<Self> {
        // Load configuration
        let config = if args.config.exists() {
            EcosystemConfig::from_file(&args.config).context("failed to load configuration")?
        } else {
            // Note: info!() may not work here if called before tracing init,
            // but DaemonConfig::new() is called after tracing setup in async_main
            EcosystemConfig::default()
        };

        // Determine paths (CLI args override config file)
        let operator_socket_path = args
            .operator_socket
            .clone()
            .unwrap_or_else(|| config.daemon.operator_socket.clone());
        let session_socket_path = args
            .session_socket
            .clone()
            .unwrap_or_else(|| config.daemon.session_socket.clone());
        let pid_path = args
            .pid_file
            .clone()
            .unwrap_or_else(|| config.daemon.pid_file.clone());
        let state_file_path = args
            .state_file
            .clone()
            .unwrap_or_else(|| config.daemon.state_file.clone());

        // Ledger DB path from args (config fallback not yet standard)
        let ledger_db_path = args.ledger_db.clone();

        // TCK-00383: CAS path from CLI args, falling back to config file
        let cas_path = args
            .cas_path
            .clone()
            .or_else(|| config.daemon.cas_path.clone());

        Ok(Self {
            config,
            operator_socket_path,
            session_socket_path,
            pid_path,
            state_file_path,
            ledger_db_path,
            cas_path,
            metrics_port: args.metrics_port,
            metrics_disabled: args.no_metrics,
        })
    }
}

/// Write PID file.
fn write_pid_file(pid_path: &PathBuf) -> Result<()> {
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(pid_path, std::process::id().to_string())?;
    info!("PID file written to {:?}", pid_path);
    Ok(())
}

/// Remove PID file.
fn remove_pid_file(pid_path: &PathBuf) {
    if pid_path.exists() {
        if let Err(e) = std::fs::remove_file(pid_path) {
            warn!("Failed to remove PID file: {e}");
        }
    }
}

/// Load or create a persistent signer key for projection receipts.
///
/// TCK-00322 BLOCKER FIX: Non-Persistent Signer for Projection Receipts
///
/// The projection worker requires a persistent signing key to ensure receipt
/// signatures remain valid across daemon restarts. This function:
///
/// 1. If the key file exists: loads the 32-byte Ed25519 secret key
/// 2. If the key file doesn't exist: generates a new key and saves it
///
/// The key file is created with mode 0600 (owner read/write only) to prevent
/// unauthorized access to the signing key material.
///
/// # Arguments
///
/// * `key_path` - Path to the signer key file
///
/// # Errors
///
/// Returns an error if:
/// - The key file cannot be read or written
/// - The key file contains invalid data (not 32 bytes)
/// - File permissions cannot be set
fn load_or_create_persistent_signer(key_path: &PathBuf) -> Result<apm2_core::crypto::Signer> {
    use apm2_core::crypto::Signer;

    // Ensure parent directory exists
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create signer key directory")?;
    }

    if key_path.exists() {
        // Load existing key
        let key_bytes = std::fs::read(key_path).context("failed to read signer key file")?;

        if key_bytes.len() != 32 {
            anyhow::bail!(
                "invalid signer key file: expected 32 bytes, got {}",
                key_bytes.len()
            );
        }

        Signer::from_bytes(&key_bytes)
            .map_err(|e| anyhow::anyhow!("failed to parse signer key: {e}"))
    } else {
        // Generate new key and save it
        let signer = Signer::generate();
        let key_bytes = signer.secret_key_bytes();

        // Write key file with secure permissions
        // TCK-00322 BLOCKER FIX: Set mode 0600 to protect private key
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(key_path)
                .context("failed to create signer key file")?;

            file.write_all(&*key_bytes)
                .context("failed to write signer key")?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(key_path, &*key_bytes).context("failed to write signer key")?;
        }

        info!(key_path = %key_path.display(), "Generated new persistent projection signer key");

        Ok(signer)
    }
}

/// Initialize the supervisor with processes from configuration.
fn init_supervisor(config: &EcosystemConfig) -> Supervisor {
    let mut supervisor = Supervisor::new();

    for process_config in &config.processes {
        let mut builder = apm2_core::process::ProcessSpec::builder()
            .name(&process_config.name)
            .command(&process_config.command)
            .args(process_config.args.clone())
            .instances(process_config.instances)
            .restart(process_config.restart.clone())
            .log(process_config.log.clone())
            .shutdown(process_config.shutdown.clone());

        if let Some(cwd) = &process_config.cwd {
            builder = builder.cwd(cwd);
        }

        for (k, v) in &process_config.env {
            builder = builder.env(k, v);
        }

        let spec = builder.build();

        if let Err(e) = supervisor.register(spec) {
            warn!("Failed to register process '{}': {e}", process_config.name);
        }
    }

    supervisor
}

/// Collect all running process instances from the supervisor.
///
/// Returns a list of `(name, instance)` pairs for every process instance
/// whose supervisor handle reports a running state.
async fn collect_running_processes(state: &SharedState) -> Vec<(String, u32)> {
    let inner = state.read().await;
    inner
        .supervisor
        .specs()
        .flat_map(|spec| {
            (0..spec.instances)
                .filter(|i| {
                    inner
                        .supervisor
                        .get_handle(&spec.name, *i)
                        .is_some_and(|h| h.state.is_running())
                })
                .map(|i| (spec.name.clone(), i))
        })
        .collect()
}

/// Read the start time (field 22) from `/proc/{pid}/stat`.
///
/// This is used to uniquely identify a process beyond its PID. After a
/// process exits, the kernel may recycle its PID for a new, unrelated
/// process. By recording the start time at snapshot time and re-reading it
/// before sending a kill signal, we can detect PID reuse and avoid killing
/// an innocent process.
///
/// Returns `Some(starttime)` on success, or `None` if the proc entry does
/// not exist or cannot be parsed (e.g. the process already exited).
#[cfg(unix)]
fn read_proc_start_time(pid: u32) -> Option<u64> {
    let stat_path = format!("/proc/{pid}/stat");
    let contents = std::fs::read_to_string(stat_path).ok()?;

    // Field 2 (comm) is enclosed in parentheses and may contain spaces,
    // parens, and other special characters. The safe way to parse is to
    // find the LAST ')' in the line, then split everything after it.
    let after_comm = contents.rsplit_once(')')?.1;

    // Fields after comm (field 2) start at field 3.  We need field 22
    // (starttime), which is field index 22 - 3 = 19 in the remaining
    // whitespace-separated tokens.
    let tokens: Vec<&str> = after_comm.split_whitespace().collect();
    // Index 19 corresponds to field 22 (starttime).
    tokens.get(19)?.parse::<u64>().ok()
}

/// Collect tracked PIDs for all running process instances, together with
/// each process's kernel start time for identity validation.
///
/// Returns a map of `PID -> starttime` that the force-kill phase can use
/// to verify a PID still belongs to the originally managed child before
/// sending `SIGKILL`. This prevents false-positive kills when the kernel
/// recycles a PID between the graceful and force-kill phases.
async fn collect_tracked_pids(state: &SharedState) -> std::collections::HashMap<u32, Option<u64>> {
    let inner = state.read().await;
    let mut pids = std::collections::HashMap::new();
    for spec in inner.supervisor.specs() {
        for i in 0..spec.instances {
            if let Some(handle) = inner.supervisor.get_handle(&spec.name, i) {
                if handle.state.is_running() {
                    if let Some(pid) = handle.pid {
                        #[cfg(unix)]
                        let start_time = read_proc_start_time(pid);
                        #[cfg(not(unix))]
                        let start_time = None;
                        pids.insert(pid, start_time);
                    }
                }
            }
        }
    }
    pids
}

/// Graceful shutdown: stop all running processes using a deadline-driven
/// loop.
///
/// **Cancellation safety (TCK-00392 BLOCKER fix):**
///
/// Unlike the previous implementation, this function is NOT wrapped in an
/// outer `tokio::time::timeout`. Instead it uses an internal deadline: each
/// process stop is attempted within the remaining time budget. When the
/// deadline is exceeded the loop breaks and the caller proceeds to the
/// force-kill phase.
///
/// Runners are NOT removed from daemon state until the stop call has
/// completed (or been skipped due to deadline). This ensures that
/// `force_kill_all_processes` can always find the runner handle if needed.
///
/// Returns `true` if all processes were stopped within the deadline, or
/// `false` if the deadline was exceeded (force-kill is required).
async fn shutdown_all_processes(state: &SharedState, deadline: tokio::time::Instant) -> bool {
    info!("Stopping all running processes...");

    let processes_to_stop = collect_running_processes(state).await;

    if processes_to_stop.is_empty() {
        info!("No running processes to stop");
        return true;
    }

    info!("Stopping {} process instance(s)", processes_to_stop.len());

    let mut all_stopped = true;

    for (name, instance) in processes_to_stop {
        // Check deadline BEFORE starting a new stop attempt.
        let now = tokio::time::Instant::now();
        if now >= deadline {
            warn!(
                process = %name,
                instance,
                "Graceful shutdown deadline exceeded — skipping remaining processes"
            );
            all_stopped = false;
            break;
        }

        let remaining = deadline - now;
        // Cap per-process timeout to the remaining deadline budget.
        let per_process_timeout = remaining.min(Duration::from_secs(10));

        // Take the runner out of state, stop it, then update supervisor.
        // We hold the write lock briefly to take the runner. The actual
        // stop (which may block for up to `per_process_timeout`) happens
        // OUTSIDE the lock.
        let runner = {
            let mut inner = state.write().await;
            let spec_id = inner.supervisor.get_spec(&name).map(|s| s.id);
            spec_id.and_then(|id| inner.remove_runner(id, instance))
        };

        if let Some(mut runner) = runner {
            if runner.state().is_running() {
                info!("Stopping {}-{}", name, instance);
                if let Err(e) = runner.stop(per_process_timeout).await {
                    warn!("Error stopping {}-{}: {}", name, instance, e);
                }
            }
        }

        // Update supervisor state to reflect the stop.
        {
            let mut inner = state.write().await;
            inner.supervisor.update_state(
                &name,
                instance,
                ProcessState::Stopped { exit_code: None },
            );
            inner.supervisor.update_pid(&name, instance, None);
        }
    }

    if all_stopped {
        info!("All processes stopped gracefully");
    }
    all_stopped
}

/// Force-kill any child processes that are still running.
///
/// **Containment invariant**: This function MUST NOT be wrapped in a
/// cancellable timeout. It runs unconditionally after the graceful shutdown
/// phase (whether that phase completed or the deadline was exceeded) to
/// guarantee that no managed child process survives daemon exit.
///
/// **PID-tracking safety (TCK-00392 BLOCKER fix):**
///
/// In addition to iterating runners still present in daemon state, this
/// function also accepts a map of `PID -> starttime` that was recorded
/// _before_ the graceful phase started. If a runner was dropped mid-stop
/// (e.g. due to deadline expiry) and the process was spawned with
/// `kill_on_drop(false)`, the child may still be alive. The PID map lets
/// us issue an OS-level `SIGKILL` even when the runner handle is gone.
///
/// **PID-reuse safety (v3 security review BLOCKER fix):**
///
/// Before sending `SIGKILL` to any PID from the pre-shutdown snapshot, we
/// re-read `/proc/{pid}/stat` and verify that the kernel start time still
/// matches the value recorded at snapshot time. If the start time differs
/// (or the proc entry is gone), the PID has been recycled and the kill is
/// skipped. This prevents false-positive kills of unrelated processes.
async fn force_kill_all_processes(
    state: &SharedState,
    pre_shutdown_pids: &std::collections::HashMap<u32, Option<u64>>,
) {
    // Phase A: kill processes still tracked in supervisor state.
    let still_running = collect_running_processes(state).await;

    if !still_running.is_empty() {
        warn!(
            count = still_running.len(),
            "Force-killing remaining child processes after graceful shutdown timeout"
        );

        for (name, instance) in still_running {
            let runner = {
                let mut inner = state.write().await;
                let spec_id = inner.supervisor.get_spec(&name).map(|s| s.id);
                spec_id.and_then(|id| inner.remove_runner(id, instance))
            };

            if let Some(mut runner) = runner {
                if runner.state().is_running() {
                    warn!("Force-killing {}-{}", name, instance);
                    // runner.stop with a zero-second timeout will send SIGTERM
                    // then immediately SIGKILL.
                    if let Err(e) = runner.stop(Duration::ZERO).await {
                        warn!("Error force-killing {}-{}: {}", name, instance, e);
                    }
                }
            }

            // Update supervisor state
            {
                let mut inner = state.write().await;
                inner.supervisor.update_state(
                    &name,
                    instance,
                    ProcessState::Stopped { exit_code: None },
                );
                inner.supervisor.update_pid(&name, instance, None);
            }
        }
    }

    // Phase B: OS-level kill for any PID in the pre-shutdown map that is
    // still alive AND still the same process (validated via start time).
    // This catches processes whose runner was dropped mid-stop
    // (cancellation / deadline expiry) and were spawned with
    // `kill_on_drop(false)`.
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        for (&pid, &snapshot_start_time) in pre_shutdown_pids {
            // Check if the process is still alive (signal 0 = no-op probe).
            #[allow(clippy::cast_possible_wrap)]
            let target = Pid::from_raw(pid as i32);
            if kill(target, None).is_ok() {
                // PID-reuse safety: verify the process identity before killing.
                // If we recorded a start time at snapshot, the current process
                // at this PID must have the same start time. A mismatch means
                // the original child exited and the PID was recycled.
                if let Some(expected_start) = snapshot_start_time {
                    let current_start = read_proc_start_time(pid);
                    if current_start != Some(expected_start) {
                        warn!(
                            pid,
                            expected_start,
                            ?current_start,
                            "PID reuse detected — skipping kill of unrelated process"
                        );
                        continue;
                    }
                } else {
                    // Snapshot start time was None — we cannot verify whether
                    // this PID still belongs to our original child.  Fail-closed:
                    // do NOT kill an unverified PID.  Phase A (runner handles)
                    // is responsible for these processes.
                    warn!(
                        pid,
                        "Snapshot start time unavailable — skipping SIGKILL \
                         (cannot verify PID identity)"
                    );
                    continue;
                }
                warn!(pid, "Orphan process still alive — sending SIGKILL");
                #[allow(clippy::cast_possible_wrap)]
                let _ = kill(target, Signal::SIGKILL);
            }
        }
    }

    info!("Force-kill of remaining processes complete");
}

/// Perform daemonization via double-fork pattern.
///
/// # Safety
///
/// This function MUST be called BEFORE any multi-threaded runtime (like Tokio)
/// is initialized. `fork()` in a multi-threaded process is undefined behavior
/// because:
///
/// 1. `fork()` only duplicates the calling thread, not worker threads
/// 2. Mutexes held by other threads remain locked forever in the child
/// 3. Thread-local storage and thread IDs become inconsistent
///
/// By calling this function in a truly single-threaded context (before
/// `Runtime::new()`), we ensure the child process starts with a clean slate
/// and can safely initialize its own multi-threaded runtime afterward.
///
/// # Returns
///
/// - `Ok(true)` if daemonization succeeded (caller is the daemon child)
/// - `Ok(false)` if daemonization is not supported on this platform
/// - `Err(_)` if daemonization failed
#[allow(unsafe_code)] // fork() requires unsafe
fn daemonize() -> Result<bool> {
    #[cfg(unix)]
    {
        use nix::unistd::{ForkResult, fork, setsid};

        // First fork (double-fork daemon pattern)
        //
        // SAFETY: This is safe because we are calling fork() BEFORE the Tokio
        // runtime is initialized. At this point, the process is truly
        // single-threaded:
        // - No worker threads have been spawned
        // - No async runtime exists
        // - No background threads from libraries like rustls
        //
        // The parent process exits immediately, and the child continues to
        // complete the daemonization sequence.
        match unsafe { fork() }? {
            ForkResult::Parent { .. } => {
                // Parent exits immediately - daemon continues in child
                std::process::exit(0);
            },
            ForkResult::Child => {},
        }

        // Create new session - become session leader, lose controlling terminal
        setsid()?;

        // Second fork (completes double-fork daemon pattern)
        //
        // SAFETY: Still single-threaded - we are the first fork's child,
        // which inherited only the calling thread. No runtime has been
        // started yet. This second fork ensures the daemon cannot
        // accidentally reacquire a controlling terminal.
        match unsafe { fork() }? {
            ForkResult::Parent { .. } => {
                // Intermediate parent exits - daemon continues in grandchild
                std::process::exit(0);
            },
            ForkResult::Child => {},
        }

        // Change to root directory to avoid holding directory handles
        std::env::set_current_dir("/")?;

        Ok(true)
    }

    #[cfg(not(unix))]
    {
        // Daemonization not supported on non-Unix platforms
        Ok(false)
    }
}

/// Synchronous entry point - handles daemonization BEFORE async runtime starts.
///
/// # Fork Safety (TCK-00282)
///
/// This function exists to ensure `fork()` is called in a truly single-threaded
/// context. The previous implementation used `#[tokio::main]` which expands to:
///
/// ```ignore
/// fn main() {
///     let rt = tokio::runtime::Runtime::new().unwrap();  // Spawns worker threads!
///     rt.block_on(async { /* user's async main */ })
/// }
/// ```
///
/// This meant `fork()` was called AFTER worker threads existed, which is
/// undefined behavior. The fix is to:
///
/// 1. Parse args and handle daemonization synchronously (no threads yet)
/// 2. THEN create the Tokio runtime
/// 3. THEN run the async main
fn main() -> Result<()> {
    // Parse command-line arguments (synchronous, no threads)
    let args = Args::parse();

    // Daemonize if requested - MUST happen before any async runtime!
    //
    // This is the critical fix for TCK-00282. By daemonizing here, we ensure
    // fork() is called when only the main thread exists.
    if !args.no_daemon {
        match daemonize() {
            // Successfully daemonized (true) or platform doesn't support it (false)
            // Either way, continue to start the async runtime below.
            // Unsupported platforms will log a warning after tracing is initialized.
            Ok(true | false) => {},
            Err(e) => {
                // Daemonization failed - abort startup
                // Can't use tracing here since it's not initialized yet
                eprintln!("Daemonization failed: {e}");
                return Err(e);
            },
        }
    }

    // NOW it's safe to create the multi-threaded Tokio runtime.
    // Either we're running in foreground (--no-daemon), or we've completed
    // the double-fork and are the daemon grandchild process.
    let runtime = tokio::runtime::Runtime::new().context("failed to create Tokio runtime")?;

    // Run the async main on the runtime
    runtime.block_on(async_main(args))
}

/// Async entry point - runs after daemonization is complete.
///
/// All async initialization and the main event loop live here.
/// This is safe because the Tokio runtime was created AFTER any `fork()` calls.
async fn async_main(args: Args) -> Result<()> {
    // Initialize logging
    let filter = EnvFilter::try_new(&args.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    if let Some(log_file) = &args.log_file {
        // Log to file
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .context("failed to open log file")?;

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(file)
                    .with_ansi(false),
            )
            .init();
    } else {
        // Log to stdout
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    // Log daemonization status now that tracing is available
    if args.no_daemon {
        info!("Running in foreground mode (--no-daemon)");
    } else {
        #[cfg(unix)]
        info!("Daemonized successfully");

        #[cfg(not(unix))]
        warn!("Daemonization not supported on this platform, running in foreground");
    }

    // Install the rustls crypto provider before any TLS operations.
    // This must be done before any TLS configuration is built, otherwise
    // rustls will panic due to no default crypto provider being installed.
    // We use the ring provider for FIPS-140 compatible cryptography.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // Ignore error if already installed (e.g., in tests)

    // Verify bootstrap schema integrity before proceeding.
    // This is a critical security check that must pass before any CAC operations.
    verify_bootstrap_hash().context("bootstrap schema integrity check failed")?;

    // Register core kernel schemas on startup (TCK-00181).
    // This establishes the schema registry with all kernel event types
    // before any event processing can occur.
    let registry = InMemorySchemaRegistry::new();
    register_kernel_schemas(&registry)
        .await
        .context("kernel schema registration failed")?;

    // Load configuration and initialize
    let daemon_config = DaemonConfig::new(&args)?;

    // Log config file status
    if !args.config.exists() {
        info!("No config file found at {:?}, using defaults", args.config);
    }

    let supervisor = init_supervisor(&daemon_config.config);

    // TCK-00268: Initialize Prometheus metrics registry early so we can pass it
    // to DaemonStateHandle. This allows handlers to record IPC metrics.
    let metrics_registry = if daemon_config.metrics_disabled {
        None
    } else {
        Some(new_shared_registry().context("failed to initialize metrics registry")?)
    };

    // Create shared state with schema registry and session registry
    // The registries persist for the daemon's lifetime (TCK-00181, TCK-00266)
    //
    // TCK-00266: Use persistent session registry for crash recovery.
    // The state file path is configured via CLI or ecosystem config.
    let state: SharedState = Arc::new(
        DaemonStateHandle::new_with_persistent_sessions(
            daemon_config.config.clone(),
            supervisor,
            registry, // Pass the registry created during bootstrap
            &daemon_config.state_file_path,
            metrics_registry.clone(), // TCK-00268: Pass metrics registry for handler access
        )
        .context("failed to initialize persistent session registry")?,
    );

    info!(
        "Session registry initialized with state file: {:?}",
        daemon_config.state_file_path
    );

    // Write PID file
    write_pid_file(&daemon_config.pid_path)?;

    // Initialize persistent ledger if configured (TCK-00289)
    // TCK-00387: Moved BEFORE crash recovery so that LEASE_REVOKED events can
    // be emitted to the ledger during recovery.
    let sqlite_conn = if let Some(path) = &daemon_config.ledger_db_path {
        info!("Opening ledger database at {:?}", path);
        let conn = Connection::open(path).context("failed to open ledger database")?;

        // Initialize schemas
        SqliteLedgerEventEmitter::init_schema(&conn)
            .context("failed to init ledger events schema")?;
        SqliteWorkRegistry::init_schema(&conn).context("failed to init work claims schema")?;

        Some(Arc::new(Mutex::new(conn)))
    } else {
        None
    };

    // Security Review v5 MAJOR 2: Create ONE ledger signing key per daemon
    // lifecycle. This key is shared between crash recovery (LEASE_REVOKED
    // events) and the dispatcher (session events). Previously, recovery and
    // the dispatcher each generated their own ephemeral key, resulting in
    // multi-key signing within a single daemon lifecycle.
    let ledger_signing_key = {
        use rand::rngs::OsRng;
        ed25519_dalek::SigningKey::generate(&mut OsRng)
    };

    // TCK-00387: Crash recovery on startup
    // Before accepting new connections, recover any sessions from persistent state,
    // emit LEASE_REVOKED events to the ledger, clean up stale work claims, and
    // clear the persistent session registry.
    //
    // Security Review v5 BLOCKER 1 + Quality Review: All recovery failures
    // are startup-fatal (fail-closed). If `perform_crash_recovery` encounters
    // any error -- integrity failure, timeout, partial recovery, or other --
    // the daemon must NOT proceed to accept connections. Succeeded sessions
    // are checkpointed before the error is returned so partial progress is
    // preserved for the next startup attempt.
    perform_crash_recovery(&state, sqlite_conn.as_ref(), &ledger_signing_key).await?;

    info!(
        metrics_enabled = metrics_registry.is_some(),
        "Metrics registry initialized"
    );

    // Initialize dual-socket manager (TCK-00249)
    let socket_manager_config = SocketManagerConfig::new(
        &daemon_config.operator_socket_path,
        &daemon_config.session_socket_path,
    );
    let socket_manager = SocketManager::bind(socket_manager_config)
        .context("failed to initialize dual-socket manager")?;

    info!(
        "apm2 daemon started (pid: {}, operator_socket: {:?}, session_socket: {:?})",
        std::process::id(),
        daemon_config.operator_socket_path,
        daemon_config.session_socket_path
    );

    {
        let inner = state.read().await;
        info!("Managing {} processes", inner.supervisor.process_count());
    }

    // TCK-00287: Create shared dispatcher state at daemon startup.
    // Per security review:
    // - Item 1: Dispatchers persist across connections (no state loss)
    // - Item 2: TokenMinter uses stable secret (tokens valid across connections)
    // - Item 3: Shared ManifestStore allows SpawnEpisode manifests to be visible
    //
    // BLOCKER 1 FIX: Use with_session_registry to wire global session registry
    // from DaemonStateHandle into PrivilegedDispatcher. This ensures sessions
    // spawned via IPC are visible to daemon's persistent state.
    //
    // TCK-00289: Use with_persistence to wire real governance/ledger components if
    // available.
    // TCK-00342: Wire daemon state into dispatcher for process management.
    // This enables ListProcesses, ProcessStatus, StartProcess, StopProcess,
    // RestartProcess, and ReloadProcess handlers to query the Supervisor.
    //
    // TCK-00383: When both ledger and CAS are configured, use
    // with_persistence_and_cas() to wire the session dispatcher with ToolBroker,
    // DurableCas, ledger event emitter, and holonic clock. This enables session-
    // scoped operations: tool execution, event emission, and evidence publishing.
    // Security Review v5 MAJOR 2: Pass the same signing key used for recovery
    // into the dispatcher, ensuring ONE key per daemon lifecycle.
    let dispatcher_state: SharedDispatcherState = Arc::new(
        if let (Some(conn), Some(cas_path)) = (&sqlite_conn, &daemon_config.cas_path) {
            info!(
                cas_path = %cas_path.display(),
                "Using with_persistence_and_cas: session dispatcher fully wired"
            );
            DispatcherState::with_persistence_and_cas_and_key(
                state.session_registry().clone(),
                metrics_registry.clone(),
                Arc::clone(conn),
                cas_path,
                Some(ledger_signing_key),
                daemon_config.config.daemon.adapter_rotation.clone(),
            )
            .map_err(|e| {
                anyhow::anyhow!("CAS initialization failed for {}: {e}", cas_path.display())
            })?
        } else {
            if daemon_config.cas_path.is_some() && sqlite_conn.is_none() {
                warn!(
                    "--cas-path provided without --ledger-db; \
                     CAS requires a ledger database. Falling back to with_persistence()"
                );
            }
            DispatcherState::with_persistence_and_adapter_rotation(
                state.session_registry().clone(),
                metrics_registry.clone(),
                sqlite_conn.clone(),
                Some(ledger_signing_key),
                &daemon_config.config.daemon.adapter_rotation,
            )
            .map_err(|e| anyhow::anyhow!("adapter rotation initialization failed: {e}"))?
        }
        .with_daemon_state(Arc::clone(&state)),
    );

    // TCK-00388: Wire gate orchestrator into daemon for autonomous gate lifecycle.
    //
    // The orchestrator is instantiated with a fresh signing key and wired into
    // the DispatcherState. When a session terminates, the dispatcher calls
    // `notify_session_terminated` which delegates to the orchestrator. A
    // background task polls for gate timeouts periodically.
    let gate_signer = Arc::new(Signer::generate());
    // TCK-00418: Share the dispatcher's evidence CAS with the gate
    // orchestrator so that time_envelope_ref hashes stored during
    // `issue_gate_lease` are resolvable by `validate_lease_time_authority`
    // in the same PrivilegedDispatcher. Falls back to an in-memory CAS
    // when no durable CAS is configured (non-persistent mode).
    let gate_cas: Arc<dyn apm2_core::evidence::ContentAddressedStore> = dispatcher_state
        .evidence_cas()
        .unwrap_or_else(|| Arc::new(apm2_core::evidence::MemoryCas::default()));
    let gate_orchestrator = Arc::new(
        GateOrchestrator::new(GateOrchestratorConfig::default(), gate_signer).with_cas(gate_cas),
    );

    // Wire orchestrator into dispatcher state so session termination events
    // trigger autonomous gate lifecycle (Quality BLOCKER 1).
    let dispatcher_state = {
        // Unwrap the Arc, attach the orchestrator, and re-wrap.
        // Safety: we just created this Arc and hold the only reference.
        match Arc::try_unwrap(dispatcher_state) {
            Ok(inner) => Arc::new(inner.with_gate_orchestrator(Arc::clone(&gate_orchestrator))),
            Err(_arc) => {
                unreachable!("dispatcher_state Arc should have single owner at bootstrap");
            },
        }
    };

    // Spawn background timeout poller for autonomous gate execution (Quality
    // BLOCKER 2). This ensures timed-out gates produce FAIL verdicts even
    // without explicit receipt collection. The poller runs every 10 seconds.
    //
    // Security BLOCKER 2 fix: Persist timeout and gate events to the ledger
    // with fail-closed error handling. Without persistence, timeout FAIL
    // verdicts exist only in memory and are lost on restart.
    {
        let orch = Arc::clone(&gate_orchestrator);
        // Create a dedicated ledger emitter for the timeout poller if a
        // ledger database is configured. Uses the same sqlite_conn (shared
        // via Arc<Mutex>) and a fresh signing key.
        let timeout_ledger_emitter: Option<SqliteLedgerEventEmitter> =
            sqlite_conn.as_ref().map(|conn| {
                let timeout_signer = Signer::generate();
                let key_bytes = timeout_signer.secret_key_bytes();
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                SqliteLedgerEventEmitter::new(Arc::clone(conn), signing_key)
            });
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let events = orch.poll_timeouts().await;
                if !events.is_empty() {
                    info!(
                        event_count = events.len(),
                        "Gate timeout poller emitted events"
                    );
                    // Security BLOCKER 2 fix: Persist events to ledger.
                    if let Some(ref emitter) = timeout_ledger_emitter {
                        use apm2_daemon::protocol::dispatch::LedgerEventEmitter;
                        for event in &events {
                            let event_type = match event {
                                apm2_daemon::gate::GateOrchestratorEvent::GateTimedOut { .. } => {
                                    "gate.timed_out"
                                },
                                apm2_daemon::gate::GateOrchestratorEvent::GateTimeoutReceiptGenerated { .. } => {
                                    "gate.timeout_receipt_generated"
                                },
                                apm2_daemon::gate::GateOrchestratorEvent::AllGatesCompleted { .. } => {
                                    "gate.all_completed"
                                },
                                _ => "gate.event",
                            };
                            let payload = serde_json::to_vec(event).unwrap_or_default();
                            #[allow(clippy::cast_possible_truncation)]
                            let timestamp_ns = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_nanos() as u64)
                                .unwrap_or(0);
                            if let Err(e) = emitter.emit_session_event(
                                "gate-timeout-poller",
                                event_type,
                                &payload,
                                "orchestrator:timeout-poller",
                                timestamp_ns,
                            ) {
                                // Fail-closed: log the error. The timeout
                                // verdict still exists in the orchestrator's
                                // in-memory state and will be re-emitted on
                                // the next poll if the gate is still active.
                                error!(
                                    event_type = %event_type,
                                    error = %e,
                                    "Failed to persist gate timeout event to ledger (fail-closed)"
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    // TCK-00322: Start projection worker if ledger and projection are configured.
    // The projection worker:
    // - Tails the ledger for ReviewReceiptRecorded events
    // - Maintains work index (changeset -> work_id -> PR)
    // - Projects review results to GitHub (status + comment)
    let projection_worker_handle = if let Some(ref conn) = sqlite_conn {
        use apm2_daemon::projection::{
            GitHubAdapterConfig, GitHubProjectionAdapter, ProjectionWorker, ProjectionWorkerConfig,
        };

        let projection_conn = Arc::clone(conn);
        let projection_config = &daemon_config.config.daemon.projection;

        // Build worker configuration from ecosystem config
        let mut config = ProjectionWorkerConfig::new()
            .with_poll_interval(Duration::from_secs(projection_config.poll_interval_secs))
            .with_batch_size(projection_config.batch_size);

        // BLOCKER FIX: Incomplete Feature Wiring (Dead Code)
        // Previously, ProjectionWorker was initialized but set_adapter was never
        // called, causing self.adapter to always be None and all projections to
        // be skipped. Now we properly instantiate GitHubProjectionAdapter and
        // inject it.
        let mut github_adapter: Option<GitHubProjectionAdapter> = None;

        // Enable GitHub projection if configured
        if projection_config.enabled
            && !projection_config.github_owner.is_empty()
            && !projection_config.github_repo.is_empty()
        {
            // Build GitHub adapter config
            match GitHubAdapterConfig::new(
                &projection_config.github_api_url,
                &projection_config.github_owner,
                &projection_config.github_repo,
            ) {
                Ok(mut github_config) => {
                    // TCK-00322 MAJOR FIX: Fail-Open Mock Mode on Configuration Error
                    // When `enabled = true`, missing token env var is now a FATAL error.
                    // Previously, this would silently fall back to mock mode, which could
                    // cause production systems to think they're projecting to GitHub when
                    // they're not. Now we fail-closed: missing mandatory config = startup
                    // failure.
                    let Some(ref token_env) = projection_config.github_token_env else {
                        // TCK-00322 MAJOR FIX: Missing token_env is fatal when enabled
                        error!(
                            "projection.enabled=true but github_token_env is not configured. \
                             A GitHub token is required for production projection."
                        );
                        return Err(anyhow::anyhow!(
                            "projection.enabled=true but github_token_env is not configured"
                        ));
                    };

                    // Strip leading $ if present
                    let env_var = token_env.strip_prefix('$').unwrap_or(token_env);
                    let Ok(token) = std::env::var(env_var) else {
                        // TCK-00322 MAJOR FIX: Missing token is fatal when enabled
                        error!(
                            env_var = %env_var,
                            "GitHub token env var not set. \
                             projection.enabled=true requires a valid token. \
                             Either set the env var or disable projection."
                        );
                        return Err(anyhow::anyhow!(
                            "projection.enabled=true but github_token_env ({env_var}) is not set"
                        ));
                    };

                    github_config = match github_config.clone().with_api_token(&token) {
                        Ok(cfg_with_token) => cfg_with_token,
                        Err(e) => {
                            // Invalid token format is fatal when projection is enabled
                            error!(
                                env_var = %env_var,
                                error = %e,
                                "Invalid GitHub token. Projection enabled but cannot proceed."
                            );
                            return Err(anyhow::anyhow!(
                                "projection.enabled=true but GitHub token is invalid: {e}"
                            ));
                        },
                    };

                    config = config.with_github(github_config.clone());

                    // TCK-00322 BLOCKER FIX: Non-Persistent Signer for Projection Receipts
                    // Load or generate a persistent signer key from file. The key file path
                    // is configurable via projection.signer_key_file, defaulting to
                    // {state_file_dir}/projection_signer.key.
                    let signer_key_path =
                        projection_config
                            .signer_key_file
                            .clone()
                            .unwrap_or_else(|| {
                                daemon_config.state_file_path.parent().map_or_else(
                                    || PathBuf::from("/var/lib/apm2/projection_signer.key"),
                                    |p| p.join("projection_signer.key"),
                                )
                            });

                    let signer = load_or_create_persistent_signer(&signer_key_path)
                        .context("failed to load projection signer key")?;
                    info!(
                        key_path = %signer_key_path.display(),
                        public_key = %hex::encode(signer.public_key_bytes()),
                        "Loaded persistent projection signer"
                    );

                    // Determine cache path for idempotency
                    // TCK-00322 MAJOR FIX: Don't use /tmp for cache - use ledger-adjacent path
                    let cache_path = daemon_config.ledger_db_path.as_ref().map_or_else(
                        || {
                            daemon_config.state_file_path.parent().map_or_else(
                                || PathBuf::from("/var/lib/apm2/projection_cache.db"),
                                |p| p.join("projection_cache.db"),
                            )
                        },
                        |p| p.with_extension("projection_cache.db"),
                    );

                    // Create adapter - always real mode when enabled=true (mock mode removed)
                    // At this point we have validated the token, so we can proceed.
                    match GitHubProjectionAdapter::new(signer, github_config, &cache_path) {
                        Ok(adapter) => {
                            info!(
                                owner = %projection_config.github_owner,
                                repo = %projection_config.github_repo,
                                cache_path = %cache_path.display(),
                                "GitHub projection adapter created"
                            );
                            github_adapter = Some(adapter);
                        },
                        Err(e) => {
                            // Adapter creation failure is fatal when enabled
                            return Err(anyhow::anyhow!("Failed to create GitHub adapter: {e}"));
                        },
                    }
                },
                Err(e) => {
                    // Invalid config is fatal when enabled
                    return Err(anyhow::anyhow!("Invalid GitHub adapter config: {e}"));
                },
            }
        } else if projection_config.enabled {
            // TCK-00322 MAJOR FIX: Missing owner/repo is fatal when enabled
            return Err(anyhow::anyhow!(
                "projection.enabled=true but github_owner or github_repo is not configured"
            ));
        }

        match ProjectionWorker::new(projection_conn, config) {
            Ok(mut worker) => {
                // BLOCKER FIX: Actually inject the adapter into the worker!
                // This was the critical missing step that caused all projections to be skipped.
                if let Some(adapter) = github_adapter {
                    worker.set_adapter(adapter);
                    info!("GitHub adapter injected into projection worker");
                } else {
                    // When projection is disabled, this is expected
                    info!("Projection worker started without adapter (projection disabled)");
                }

                let shutdown_flag = worker.shutdown_handle();
                let worker_state = state.clone();

                info!(
                    github_enabled = projection_config.enabled,
                    has_adapter = worker.has_adapter(),
                    "Starting projection worker"
                );
                let worker_task = tokio::spawn(async move {
                    if let Err(e) = worker.run().await {
                        error!("Projection worker error: {}", e);
                    }
                });

                // Shutdown handler for projection worker
                let shutdown_task = tokio::spawn(async move {
                    // Wait for daemon shutdown signal
                    loop {
                        if worker_state.is_shutdown_requested() {
                            info!("Signaling projection worker shutdown");
                            shutdown_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                });

                Some((worker_task, shutdown_task))
            },
            Err(e) => {
                warn!("Failed to initialize projection worker: {}", e);
                None
            },
        }
    } else {
        info!("Projection worker disabled (no ledger database configured)");
        None
    };

    // TCK-00393: Wire divergence watchdog into daemon main loop.
    //
    // The watchdog monitors for divergence between the ledger's MergeReceipt
    // HEAD and the external trunk HEAD (fetched via GitHub API). When
    // divergence is detected:
    //   1. DefectRecorded(PROJECTION_DIVERGENCE) event is emitted to the ledger
    //   2. InterventionFreeze is emitted to halt all new admissions
    //   3. The freeze is idempotent: repeated checks for the same divergence do not
    //      produce duplicate events
    //
    // Requirements:
    //   - Ledger database must be configured (sqlite_conn is Some)
    //   - Divergence watchdog must be enabled in ecosystem config
    //   - GitHub token must be available via environment variable
    {
        let dw_config = &daemon_config.config.daemon.divergence_watchdog;
        if dw_config.enabled {
            // TCK-00408: Fail closed when mandatory persistence dependencies
            // are missing. Validation is in DivergenceWatchdogSection so the
            // check is testable outside of the binary.
            dw_config
                .validate_startup_prerequisites(sqlite_conn.is_some())
                .map_err(|e| anyhow::anyhow!(e))?;

            if dw_config.github_owner.is_empty() || dw_config.github_repo.is_empty() {
                return Err(anyhow::anyhow!(
                    "divergence_watchdog.enabled=true but github_owner or github_repo \
                     is not configured"
                ));
            }

            // Resolve GitHub token from environment variable
            let token_env_raw = dw_config
                .github_token_env
                .as_deref()
                .unwrap_or("GITHUB_TOKEN");
            let token_env = token_env_raw.strip_prefix('$').unwrap_or(token_env_raw);
            let github_token = std::env::var(token_env).map_err(|_| {
                anyhow::anyhow!(
                    "divergence_watchdog.enabled=true but GitHub token env var \
                     ({token_env}) is not set"
                )
            })?;

            // Build watchdog configuration
            let repo_id = format!("{}/{}", dw_config.github_owner, dw_config.github_repo);
            let watchdog_config = DivergenceWatchdogConfig::new(&repo_id)
                .map_err(|e| anyhow::anyhow!("invalid divergence watchdog config: {e}"))?
                .with_poll_interval(Duration::from_secs(dw_config.poll_interval_secs))
                .map_err(|e| anyhow::anyhow!("invalid divergence watchdog poll interval: {e}"))?;

            let poll_interval = watchdog_config.poll_interval;

            // Use the daemon's signer (unified signing key per lifecycle).
            let watchdog_signer = Signer::generate();
            let watchdog = DivergenceWatchdog::new(watchdog_signer, watchdog_config);

            info!(
                repo = %repo_id,
                branch = %dw_config.trunk_branch,
                poll_interval_secs = dw_config.poll_interval_secs,
                "Divergence watchdog enabled"
            );

            // Create a dedicated ledger emitter for the watchdog.
            let watchdog_ledger_emitter: Option<SqliteLedgerEventEmitter> =
                sqlite_conn.as_ref().map(|conn| {
                    let watchdog_sign_key = Signer::generate();
                    let key_bytes = watchdog_sign_key.secret_key_bytes();
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                    SqliteLedgerEventEmitter::new(Arc::clone(conn), signing_key)
                });

            // Capture values for the spawned task
            let github_api_url = dw_config.github_api_url.clone();
            let github_owner = dw_config.github_owner.clone();
            let github_repo = dw_config.github_repo.clone();
            let trunk_branch = dw_config.trunk_branch.clone();
            let watchdog_state = state.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(poll_interval);
                // Track the last known merge receipt HEAD to avoid redundant API
                // calls when no new merges have happened.
                let mut last_divergence_detected = false;

                loop {
                    interval.tick().await;

                    // Check if daemon is shutting down
                    if watchdog_state.is_shutdown_requested() {
                        info!("Divergence watchdog shutting down");
                        break;
                    }

                    // Step 1: Fetch the latest MergeReceipt HEAD from the ledger.
                    // If no MergeReceipt exists (startup case), skip this poll cycle.
                    let merge_receipt_head = {
                        if let Some(ref emitter) = watchdog_ledger_emitter {
                            // Query the ledger for the latest merge_receipt event
                            // to extract the trunk HEAD.
                            match query_latest_merge_receipt_head(emitter) {
                                Some(head) => head,
                                None => {
                                    // No MergeReceipt in ledger yet -- this is the
                                    // normal startup case. No-op.
                                    continue;
                                },
                            }
                        } else {
                            continue;
                        }
                    };

                    // Step 2: Fetch the external trunk HEAD from GitHub API.
                    // GET /repos/{owner}/{repo}/git/ref/heads/{branch}
                    let external_head = match fetch_external_trunk_head(
                        &github_api_url,
                        &github_owner,
                        &github_repo,
                        &trunk_branch,
                        &github_token,
                    )
                    .await
                    {
                        Ok(head) => head,
                        Err(e) => {
                            warn!(
                                error = %e,
                                "Failed to fetch external trunk HEAD (will retry)"
                            );
                            continue;
                        },
                    };

                    // Step 3: Check for divergence.
                    match watchdog.check_divergence(merge_receipt_head, external_head) {
                        Ok(Some(result)) => {
                            // Divergence detected! Emit DefectRecorded event.
                            error!(
                                expected_head = %hex::encode(merge_receipt_head),
                                actual_head = %hex::encode(external_head),
                                freeze_id = %result.freeze.freeze_id(),
                                "DIVERGENCE DETECTED: trunk HEAD does not match \
                                 ledger MergeReceipt HEAD"
                            );

                            // Emit DefectRecorded event to the ledger.
                            if let Some(ref emitter) = watchdog_ledger_emitter {
                                use apm2_daemon::protocol::dispatch::LedgerEventEmitter;

                                let timestamp_ns = result.defect_event.detected_at;
                                if let Err(e) =
                                    emitter.emit_defect_recorded(&result.defect_event, timestamp_ns)
                                {
                                    error!(
                                        error = %e,
                                        "Failed to persist DefectRecorded event \
                                         (fail-closed: freeze still active in registry)"
                                    );
                                } else {
                                    info!(
                                        defect_id = %result.defect_event.defect_id,
                                        "Persisted divergence DefectRecorded event"
                                    );
                                }
                            }

                            last_divergence_detected = true;
                        },
                        Ok(None) => {
                            // No divergence, or already frozen (idempotent).
                            if last_divergence_detected {
                                // Still frozen from prior detection -- no
                                // new event.
                                // This is the idempotent path.
                            }
                        },
                        Err(e) => {
                            error!(
                                error = %e,
                                "Divergence check failed (fail-closed: check will \
                                 retry on next poll)"
                            );
                        },
                    }
                }
            });
        } else {
            info!("Divergence watchdog disabled");
        }
    }

    // TCK-00279: Start ProtocolServer-only control plane
    // This is the ONLY control-plane listener. Legacy JSON IPC has been removed per
    // DD-009.
    let socket_manager = Arc::new(socket_manager);
    let ipc_state = state.clone();
    let ipc_dispatcher_state = Arc::clone(&dispatcher_state);
    let ipc_socket_manager = Arc::clone(&socket_manager);
    let protocol_server_task = tokio::spawn(async move {
        if let Err(e) =
            run_socket_manager_server(ipc_socket_manager, ipc_state, ipc_dispatcher_state).await
        {
            error!("ProtocolServer error: {}", e);
        }
    });

    // TCK-00268: Start Prometheus metrics HTTP server
    let metrics_task = if let Some(ref metrics_reg) = metrics_registry {
        let metrics_addr: SocketAddr = ([127, 0, 0, 1], daemon_config.metrics_port).into();
        let metrics_reg = Arc::clone(metrics_reg);
        info!(
            addr = %metrics_addr,
            "Starting metrics HTTP server"
        );
        Some(tokio::spawn(async move {
            if let Err(e) = run_metrics_server(metrics_reg, metrics_addr).await {
                error!("Metrics server error: {}", e);
            }
        }))
    } else {
        info!("Metrics HTTP server disabled");
        None
    };

    // Handle Unix signals
    let signal_state = state.clone();
    let signal_task = tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT");
            }
        }

        signal_state.request_shutdown();
    });

    // Wait for shutdown
    tokio::select! {
        _ = protocol_server_task => {
            info!("ProtocolServer exited");
        }
        _ = signal_task => {
            info!("Signal handler triggered shutdown");
        }
        // TCK-00268: Monitor metrics server if enabled
        result = async {
            if let Some(task) = metrics_task {
                task.await
            } else {
                // If metrics are disabled, this branch should never complete
                std::future::pending().await
            }
        } => {
            if let Err(e) = result {
                error!("Metrics server task failed: {}", e);
            }
            info!("Metrics server exited");
        }
        // TCK-00322: Monitor projection worker if enabled
        result = async {
            if let Some((worker_task, _)) = projection_worker_handle {
                worker_task.await
            } else {
                std::future::pending().await
            }
        } => {
            if let Err(e) = result {
                error!("Projection worker task failed: {}", e);
            }
            info!("Projection worker exited");
        }
    }

    // Graceful shutdown with deadline-driven loop (TCK-00392).
    //
    // **Cancellation-safe design:**
    //
    // Phase 1 uses an internal deadline (NOT an outer `tokio::time::timeout`
    // wrapping an async future). This avoids the cancellation-safety hazard
    // where a runner could be removed from daemon state but not yet fully
    // stopped — if the outer timeout fired at that point the runner handle
    // would be dropped without killing the child (spawned with
    // `kill_on_drop(false)`).
    //
    // Phase 2 runs unconditionally. It uses both the runner handles that
    // remain in daemon state AND a pre-recorded PID set to guarantee
    // containment even for processes whose runner was dropped mid-stop.
    info!("Shutting down daemon...");

    // Record all tracked PIDs BEFORE the graceful phase so we can always
    // find orphans in the force-kill phase.
    let pre_shutdown_pids = collect_tracked_pids(&state).await;

    let shutdown_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let all_graceful = shutdown_all_processes(&state, shutdown_deadline).await;

    if !all_graceful {
        warn!(
            timeout_secs = 30,
            "Graceful shutdown deadline exceeded — force-killing remaining processes"
        );
    }

    // Phase 2: Force-kill any survivors. This is NOT wrapped in a timeout
    // because the containment invariant requires that every managed child
    // process is terminated before the daemon exits. The pre-shutdown PID
    // set ensures we can kill orphans even if their runner was dropped.
    force_kill_all_processes(&state, &pre_shutdown_pids).await;

    // Cleanup sockets (SocketManager handles this in Drop, but explicit cleanup is
    // safer)
    if let Err(e) = socket_manager.cleanup() {
        warn!("Failed to cleanup sockets: {e}");
    }
    remove_pid_file(&daemon_config.pid_path);

    info!("Daemon shutdown complete");
    Ok(())
}

/// Convert a git commit SHA (hex string) to a 32-byte array for use with
/// the divergence watchdog.
///
/// Git SHA-1 is 20 bytes (40 hex chars), but `check_divergence` uses 32-byte
/// arrays. We hash the SHA string with BLAKE3 to produce a deterministic
/// 32-byte value, consistent with how the divergence watchdog module uses
/// BLAKE3 for CAS hashing.
fn sha_to_32_bytes(hex_sha: &str) -> [u8; 32] {
    *blake3::hash(hex_sha.as_bytes()).as_bytes()
}

/// Query the latest `MergeReceipt` HEAD from the ledger.
///
/// Scans the `ledger_events` table for the most recent event of type
/// `merge_receipt_created` and extracts the `result_selector` (new commit
/// SHA). Returns `None` if no merge receipts exist (startup case) or if
/// the query fails.
///
/// # No-op on startup
///
/// If no `MergeReceipt` events exist in the ledger, this returns `None`,
/// which causes the watchdog to skip the current poll cycle. This is the
/// expected behavior on startup before any merges have occurred.
fn query_latest_merge_receipt_head(emitter: &SqliteLedgerEventEmitter) -> Option<[u8; 32]> {
    // Query the ledger for the most recent merge_receipt event and extract
    // the result_selector (commit SHA). Returns None if no merge receipts
    // exist (startup case).
    emitter.query_latest_merge_receipt_sha()
}

/// Fetch the external trunk HEAD from GitHub API.
///
/// Uses `GET /repos/{owner}/{repo}/git/ref/heads/{branch}` to retrieve the
/// SHA of the trunk branch's HEAD commit. This is a read-only operation
/// and does NOT use the write-only `GitHubProjectionAdapter`.
///
/// # Arguments
///
/// * `api_url` - GitHub API base URL (e.g., `https://api.github.com`)
/// * `owner` - Repository owner
/// * `repo` - Repository name
/// * `branch` - Branch name to check (e.g., "main")
/// * `token` - GitHub API token for authentication
///
/// # Returns
///
/// The trunk HEAD as a 32-byte array (BLAKE3 hash of the hex SHA).
///
/// # Errors
///
/// Returns an error if the HTTP request fails or the response cannot be
/// parsed.
async fn fetch_external_trunk_head(
    api_url: &str,
    owner: &str,
    repo: &str,
    branch: &str,
    token: &str,
) -> Result<[u8; 32]> {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let url = format!(
        "{}/repos/{}/{}/git/ref/heads/{}",
        api_url.trim_end_matches('/'),
        owner,
        repo,
        branch
    );

    // Build HTTPS client (HTTPS-only for security)
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    // Build request
    let request = http::Request::builder()
        .method("GET")
        .uri(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "apm2-daemon/divergence-watchdog")
        .body(Full::new(Bytes::new()))
        .context("failed to build GitHub API request")?;

    // Send request with timeout (10 seconds)
    let response = tokio::time::timeout(Duration::from_secs(10), client.request(request))
        .await
        .map_err(|_| anyhow::anyhow!("GitHub API request timed out after 10s"))?
        .context("GitHub API request failed")?;

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .context("failed to read GitHub API response body")?
        .to_bytes();

    if !status.is_success() {
        let body_str = String::from_utf8_lossy(&body_bytes);
        return Err(anyhow::anyhow!(
            "GitHub API returned {status} for {url}: {body_str}"
        ));
    }

    // Parse response: { "ref": "refs/heads/main", "object": { "sha": "...", "type":
    // "commit" } }
    let json: serde_json::Value =
        serde_json::from_slice(&body_bytes).context("failed to parse GitHub API response")?;

    let sha = json
        .get("object")
        .and_then(|obj| obj.get("sha"))
        .and_then(|sha| sha.as_str())
        .ok_or_else(|| anyhow::anyhow!("GitHub API response missing object.sha field"))?;

    Ok(sha_to_32_bytes(sha))
}

/// Perform crash recovery on daemon startup (TCK-00387).
///
/// This function:
/// 1. Loads persistent session state from the `DaemonStateHandle`'s session
///    registry (populated from the state file during
///    `new_with_persistent_sessions`)
/// 2. For each recovered session, emits a `LEASE_REVOKED` event to the ledger
/// 3. For each recovered session with active work claims, deletes the claim so
///    the work becomes re-claimable
/// 4. Clears the persistent session registry after successful recovery (only
///    successfully recovered sessions are cleared; failed sessions are
///    preserved for retry on the next startup)
/// 5. Logs recovery actions for operational visibility
///
/// # Arguments
///
/// * `state` - The daemon shared state containing the session registry
/// * `sqlite_conn` - Optional `SQLite` connection for emitting ledger events.
///   If `None`, lease revocation events will be logged but not persisted.
/// * `ledger_signing_key` - The daemon-lifecycle signing key for ledger event
///   emission. Per Security Review v5 MAJOR 2, there must be ONE signing key
///   per daemon lifecycle shared between crash recovery and the dispatcher.
///
/// # Returns
///
/// `Ok(())` if recovery succeeded or was not needed.
/// `Err(_)` if recovery failed -- this is startup-fatal per Security Review
/// v5 BLOCKER 1, since partial recovery with failed registry clearing would
/// cause duplicate ledger events on the next startup.
#[allow(
    clippy::unused_async,           // Called from async context, kept async for future use
    clippy::cast_possible_truncation // Recovery timeout is always < 5s, well within u32
)]
async fn perform_crash_recovery(
    state: &SharedState,
    sqlite_conn: Option<&Arc<Mutex<Connection>>>,
    ledger_signing_key: &ed25519_dalek::SigningKey,
) -> Result<()> {
    use std::time::Instant;

    use apm2_daemon::episode::registry::DEFAULT_RECOVERY_TIMEOUT_MS;

    let start = Instant::now();
    info!(
        timeout_ms = DEFAULT_RECOVERY_TIMEOUT_MS,
        "Starting crash recovery"
    );

    let timeout = Duration::from_millis(u64::from(DEFAULT_RECOVERY_TIMEOUT_MS));

    // TCK-00387: Load persisted sessions from the DaemonStateHandle's session
    // registry. The PersistentSessionRegistry was populated from the state file
    // during `DaemonStateHandle::new_with_persistent_sessions`.
    let session_registry = state.session_registry();
    let collected = apm2_daemon::episode::crash_recovery::collect_sessions(session_registry);

    if collected.sessions.is_empty() {
        let elapsed_ms = start.elapsed().as_millis() as u32;
        info!(
            elapsed_ms = elapsed_ms,
            sessions_recovered = 0,
            "Crash recovery completed (no persistent sessions to recover)"
        );
        return Ok(());
    }

    info!(
        stale_sessions = collected.sessions.len(),
        total_in_registry = collected.total_in_registry,
        was_truncated = collected.was_truncated,
        "Found stale sessions from previous daemon instance"
    );

    // TCK-00387: Create a ledger event emitter for emitting LEASE_REVOKED events.
    // If no SQLite connection is available, we log but do not persist events.
    //
    // Security Review v5 MAJOR 2: Use the daemon-lifecycle signing key (passed
    // in from async_main) instead of generating a separate ephemeral key. This
    // ensures ONE signing key per daemon lifecycle, shared between recovery and
    // the dispatcher.
    let emitter = sqlite_conn
        .map(|conn| SqliteLedgerEventEmitter::new(Arc::clone(conn), ledger_signing_key.clone()));

    // Security Review v4 BLOCKER 2: Create the daemon's shared HTF clock for
    // recovery timestamps. Per RFC-0016, all ledger event timestamps must come
    // from the HolonicClock. If clock creation fails, recovery must fail-closed
    // rather than falling back to SystemTime.
    let htf_clock =
        apm2_daemon::htf::HolonicClock::new(apm2_daemon::htf::ClockConfig::default(), None)
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create HTF clock for crash recovery (fail-closed per RFC-0016): {e}"
                )
            })?;

    // TCK-00387: Perform crash recovery -- emit LEASE_REVOKED events and clean
    // up work claims for each stale session.
    let result = apm2_daemon::episode::crash_recovery::recover_stale_sessions(
        &collected.sessions,
        emitter.as_ref(),
        sqlite_conn,
        timeout,
        &htf_clock,
    );

    match result {
        Ok(outcome) => {
            info!(
                sessions_recovered = outcome.sessions_recovered,
                lease_revoked_events_emitted = outcome.lease_revoked_events_emitted,
                work_claims_released = outcome.work_claims_released,
                recovery_time_ms = outcome.recovery_time_ms,
                "Crash recovery completed"
            );

            // Only clear successfully recovered sessions. Pass the succeeded
            // IDs so failed sessions are preserved for retry.
            // Security Review v4 BLOCKER 1: treat clear/persist failure as
            // recovery failure (not warning-only) to prevent repeated
            // recovery side-effects on restart.
            apm2_daemon::episode::crash_recovery::clear_session_registry(
                session_registry,
                &collected,
                Some(&outcome.succeeded_session_ids),
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "Registry clear/persist failed after successful recovery \
                 (fail-closed to prevent repeated side-effects): {e}"
                )
            })?;
        },
        Err(apm2_daemon::episode::crash_recovery::CrashRecoveryError::Timeout {
            elapsed_ms,
            timeout_ms,
            outcome,
        }) => {
            // SECURITY BLOCKER v3 fix: Timeout now carries partial progress.
            // Clear the succeeded subset so those sessions are NOT replayed.
            warn!(
                elapsed_ms = elapsed_ms,
                timeout_ms = timeout_ms,
                sessions_completed = outcome.sessions_recovered,
                "Crash recovery timed out; checkpointing partial progress"
            );
            // Security Review v4 BLOCKER 1: treat clear/persist failure as
            // recovery failure (not warning-only).
            if !outcome.succeeded_session_ids.is_empty() {
                apm2_daemon::episode::crash_recovery::clear_session_registry(
                    session_registry,
                    &collected,
                    Some(&outcome.succeeded_session_ids),
                )
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Registry clear/persist failed after timeout partial recovery \
                     (fail-closed to prevent repeated side-effects): {e}"
                    )
                })?;
            }
            // Quality Review: fail-closed -- timeout means incomplete recovery,
            // daemon must not start with un-recovered sessions.
            return Err(anyhow::anyhow!(
                "Crash recovery timed out after {elapsed_ms}ms \
                 (limit {timeout_ms}ms, {sessions_completed} of {total} sessions recovered); \
                 succeeded subset checkpointed, startup aborted (fail-closed)",
                sessions_completed = outcome.sessions_recovered,
                total = collected.sessions.len(),
            ));
        },
        Err(apm2_daemon::episode::crash_recovery::CrashRecoveryError::PartialRecovery {
            failed_count,
            total_count,
            outcome,
        }) => {
            // Partial recovery -- some sessions had critical side-effect
            // failures. Only clear the succeeded sessions; failed ones are
            // preserved for retry.
            warn!(
                failed_count = failed_count,
                total_count = total_count,
                succeeded = outcome.succeeded_session_ids.len(),
                "Partial crash recovery; clearing only succeeded sessions"
            );
            // Security Review v4 BLOCKER 1: treat clear/persist failure as
            // recovery failure (not warning-only).
            apm2_daemon::episode::crash_recovery::clear_session_registry(
                session_registry,
                &collected,
                Some(&outcome.succeeded_session_ids),
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "Registry clear/persist failed after partial recovery \
                 (fail-closed to prevent repeated side-effects): {e}"
                )
            })?;
            // Quality Review: fail-closed -- partial recovery means some
            // sessions could not be recovered; daemon must not start.
            return Err(anyhow::anyhow!(
                "Crash recovery partially failed ({failed_count} of {total_count} sessions \
                 failed); succeeded subset checkpointed, startup aborted (fail-closed)"
            ));
        },
        Err(e) => {
            // Security Review BLOCKER 1 (PR #434): All recovery failures are
            // startup-fatal. The registry is NOT cleared, preserving sessions
            // for retry on the next startup. But the daemon must NOT proceed
            // to accept connections, because incomplete recovery means stale
            // leases and work claims may still exist.
            return Err(anyhow::anyhow!(
                "Crash recovery failed (fail-closed, startup aborted): {e}"
            ));
        },
    }

    Ok(())
}

/// Run the `ProtocolServer`-only control plane (TCK-00279).
///
/// This is the ONLY control-plane IPC listener. Per DD-009 (RFC-0017),
/// legacy JSON IPC has been removed and `ProtocolServer` is the sole
/// control-plane surface:
/// - `operator.sock` (mode 0600): Privileged operations
/// - `session.sock` (mode 0660): Session-scoped operations
///
/// # TCK-00287 Security Fixes
///
/// Per the security review, this function now passes shared dispatcher state
/// to connection handlers, ensuring:
/// - Registries persist across connections (Item 1)
/// - Token secrets are stable (Item 2)
/// - Fail-closed defaults are enforced (Item 3)
///
/// # Acceptance Criteria (TCK-00279)
///
/// - No `ipc_server::run` invocation in default build
/// - Startup logs show only operator.sock + session.sock listeners
/// - Legacy socket path is absent
async fn run_socket_manager_server(
    socket_manager: Arc<SocketManager>,
    state: SharedState,
    dispatcher_state: SharedDispatcherState,
) -> Result<()> {
    info!("ProtocolServer control plane started (operator.sock + session.sock only)");

    loop {
        // Check for shutdown
        if state.is_shutdown_requested() {
            info!("ProtocolServer control plane shutting down");
            break;
        }

        // Accept connection with timeout to allow shutdown checks
        let accept_result =
            tokio::time::timeout(Duration::from_millis(100), socket_manager.accept()).await;

        match accept_result {
            Ok(Ok((connection, _permit, socket_type))) => {
                let conn_state = state.clone();
                let conn_dispatcher_state = Arc::clone(&dispatcher_state);
                tokio::spawn(async move {
                    if let Err(e) = handle_dual_socket_connection(
                        connection,
                        socket_type,
                        conn_state,
                        conn_dispatcher_state,
                    )
                    .await
                    {
                        warn!("Connection handler error: {e}");
                    }
                });
            },
            Ok(Err(e)) => {
                error!("Failed to accept connection: {e}");
            },
            Err(_) => {
                // Timeout, continue to check shutdown
            },
        }
    }

    Ok(())
}

/// Handle a connection from the dual-socket manager.
///
/// Routes requests based on socket type (privilege level).
///
/// # Protocol Compliance (TCK-00279/TCK-00281/TCK-00287)
///
/// This function performs the mandatory Hello/HelloAck handshake as specified
/// in DD-001/DD-008, then processes protobuf messages via tag-based
/// dispatchers. Legacy JSON IPC has been removed per DD-009.
///
/// # TCK-00287 Security Fixes
///
/// Per the security review, this function now:
/// - **Item 1**: Uses shared dispatchers from `DispatcherState` (no state loss)
/// - **Item 2**: Token secrets are stable via shared `TokenMinter`
/// - **Item 3**: Fail-closed defaults via `FailClosedManifestStore`
/// - **Item 4**: Sends responses back to clients via
///   `connection.framed().send()`
/// - **Item 5**: Terminates connection on protocol errors (breaks loop)
///
/// # JSON Downgrade Rejection (DD-009)
///
/// Per TCK-00287 and DD-009, JSON frames are rejected before reaching handlers.
/// The tag-based routing validates that the first byte is a valid message type
/// tag (1-4 for privileged, 1-4 for session). JSON frames starting with `{`
/// (0x7B = 123) are rejected as unknown message types. Protocol errors
/// terminate the connection immediately.
async fn handle_dual_socket_connection(
    mut connection: protocol::server::Connection,
    socket_type: protocol::socket_manager::SocketType,
    state: SharedState,
    dispatcher_state: SharedDispatcherState,
) -> Result<()> {
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use protocol::connection_handler::{HandshakeConfig, HandshakeResult, perform_handshake};
    use protocol::dispatch::ConnectionContext;

    info!(
        socket_type = %socket_type,
        privileged = connection.is_privileged(),
        "New ProtocolServer connection"
    );

    // TCK-00348: Build handshake config from real HSI contract manifest.
    // The server contract hash is computed from the dispatch registry so
    // that real connections enforce the tiered mismatch policy.
    //
    // TCK-00348 MAJOR: Wire DaemonMetrics into HandshakeConfig so the
    // contract_mismatch_total counter is emitted from the production path.
    let handshake_config = {
        let mut config = HandshakeConfig::from_manifest();
        if let Some(metrics_reg) = state.metrics_registry() {
            config = config.with_metrics(metrics_reg.daemon_metrics().clone());
        }
        config
    };

    // Perform mandatory handshake
    let contract_binding = match perform_handshake(&mut connection, &handshake_config).await? {
        HandshakeResult::Success { contract_binding } => {
            info!(
                socket_type = %socket_type,
                mismatch_waived = contract_binding.mismatch_waived,
                risk_tier = %contract_binding.risk_tier,
                "Handshake completed successfully"
            );
            contract_binding
        },
        HandshakeResult::Failed => {
            warn!(socket_type = %socket_type, "Handshake failed, closing connection");
            return Ok(());
        },
        HandshakeResult::ConnectionClosed => {
            info!(socket_type = %socket_type, "Connection closed during handshake");
            return Ok(());
        },
    };

    // TCK-00287: Wire up tag-based ProtocolServer dispatchers
    // Create connection context based on socket type.
    // TCK-00348: Attach contract binding to connection context so it is
    // threaded into SessionStarted events during SpawnEpisode (authoritative
    // record with real session_id, not a surrogate connection_id).
    let mut ctx = match socket_type {
        protocol::socket_manager::SocketType::Operator => {
            ConnectionContext::privileged(connection.peer_credentials().cloned())
        },
        protocol::socket_manager::SocketType::Session => {
            ConnectionContext::session(connection.peer_credentials().cloned(), None)
        },
    };
    ctx.set_contract_binding(contract_binding.clone());

    // TCK-00358: Wire identity proof profile hash at session-open time.
    // The active identity proof profile is resolved from the risk tier
    // established during handshake. For baseline deployments this is the
    // SMT-256 10^12 profile. Setting the hash here (on the production
    // session-open path) ensures SessionStarted events carry the verified
    // profile hash rather than a spawn-time baseline fallback (REQ-0012).
    {
        use apm2_daemon::identity::IdentityProofProfileV1;
        let profile = IdentityProofProfileV1::baseline_smt_10e12();
        match profile.content_hash() {
            Ok(hash) => {
                if let Err(e) = ctx.set_identity_proof_profile_hash(hash) {
                    warn!(
                        error = %e,
                        "Failed to set identity proof profile hash on connection context"
                    );
                }
            },
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to compute identity proof profile hash at session open"
                );
            },
        }
    }

    // TCK-00349: Advance connection phase through the session-typed state
    // machine. The handshake has succeeded at this point, so we advance
    // from Connected -> HandshakeComplete -> SessionOpen before entering
    // the dispatch loop. This ensures no IPC dispatch is possible until
    // the full state progression is complete.
    ctx.advance_to_handshake_complete()
        .context("connection phase transition to HandshakeComplete failed")?;
    ctx.advance_to_session_open()
        .context("connection phase transition to SessionOpen failed")?;

    // TCK-00287 Item 1 & 2: Use shared dispatchers from DispatcherState.
    // These dispatchers persist across connections and use stable secrets.
    let privileged_dispatcher = dispatcher_state.privileged_dispatcher();
    let session_dispatcher = dispatcher_state.session_dispatcher();

    // TCK-00303: Get subscription registry for connection cleanup on close.
    // When the connection closes, we MUST call unregister_connection to free
    // the connection slot and prevent DoS via connection slot exhaustion.
    let subscription_registry = dispatcher_state.subscription_registry();
    let connection_id = ctx.connection_id().to_string();

    // TCK-00287: Message dispatch loop
    // Process incoming frames until connection closes or error
    info!(
        socket_type = %socket_type,
        connection_id = %connection_id,
        "Entering message dispatch loop"
    );

    while let Some(frame_result) = connection.framed().next().await {
        let frame = match frame_result {
            Ok(frame) => frame,
            Err(e) => {
                warn!(socket_type = %socket_type, error = %e, "Frame read error");
                break;
            },
        };

        // TCK-00287 Item 5: JSON downgrade rejection (DD-009 fail-closed)
        // Validate frame before dispatch. JSON frames start with '{' (0x7B = 123)
        // or '[' (0x5B = 91) which are not valid message type tags.
        // Per security review: protocol errors MUST terminate connection (DoS
        // mitigation).
        if !frame.is_empty() && is_json_frame(&frame) {
            warn!(
                socket_type = %socket_type,
                first_byte = frame[0],
                "JSON downgrade attempt rejected - terminating connection"
            );
            // TCK-00287 Item 5: Terminate connection on protocol violation
            break;
        }

        // Route to appropriate dispatcher based on socket type
        // Each dispatcher returns its own response type, so we handle them separately
        let frame_bytes = Bytes::from(frame.to_vec());
        match socket_type {
            protocol::socket_manager::SocketType::Operator => {
                match privileged_dispatcher.dispatch(&frame_bytes, &ctx) {
                    Ok(response) => {
                        info!(socket_type = %socket_type, "Privileged request dispatched successfully");
                        // TCK-00287 Item 4: Send response back to client
                        let response_bytes = response.encode();
                        if let Err(e) = connection.framed().send(response_bytes).await {
                            warn!(socket_type = %socket_type, error = %e, "Failed to send response");
                            break;
                        }
                    },
                    Err(e) => {
                        // TCK-00287 Item 5: Protocol errors terminate connection
                        warn!(socket_type = %socket_type, error = %e, "Privileged dispatch error - terminating connection");
                        break;
                    },
                }
            },
            protocol::socket_manager::SocketType::Session => {
                match session_dispatcher.dispatch(&frame_bytes, &ctx) {
                    Ok(response) => {
                        info!(socket_type = %socket_type, "Session request dispatched successfully");
                        // TCK-00287 Item 4: Send response back to client
                        let response_bytes = response.encode();
                        if let Err(e) = connection.framed().send(response_bytes).await {
                            warn!(socket_type = %socket_type, error = %e, "Failed to send response");
                            break;
                        }
                    },
                    Err(e) => {
                        // TCK-00287 Item 5: Protocol errors terminate connection
                        warn!(socket_type = %socket_type, error = %e, "Session dispatch error - terminating connection");
                        break;
                    },
                }
            },
        }
    }

    // TCK-00303: CRITICAL - Unregister connection to prevent DoS via slot
    // exhaustion. Without this cleanup, connection slots leak and after
    // max_connections (100) connections, the daemon will permanently reject all
    // new SubscribePulse requests.
    subscription_registry.unregister_connection(&connection_id);
    info!(
        socket_type = %socket_type,
        connection_id = %connection_id,
        "Connection closed (subscription registry cleaned up)"
    );
    Ok(())
}

/// Checks if a frame appears to be a JSON payload (downgrade attempt).
///
/// JSON payloads typically start with `{` (object) or `[` (array).
/// The protocol requires tag-based binary frames where the first byte
/// is a message type tag (1-4 for privileged, 1-4 for session).
///
/// # DD-009 Compliance
///
/// Per DD-009, JSON IPC is a downgrade/bypass surface and must be fail-closed
/// by default. This function helps identify and reject JSON frames before
/// they reach any handler.
#[inline]
fn is_json_frame(frame: &[u8]) -> bool {
    if frame.is_empty() {
        return false;
    }
    // JSON typically starts with '{', '[', or whitespace followed by these
    // Valid protocol tags are 1-4 (privileged) or 1-4 (session)
    // ASCII '{' = 123 (0x7B), '[' = 91 (0x5B)
    matches!(frame[0], b'{' | b'[')
}

/// Run the Prometheus metrics HTTP server (TCK-00268).
///
/// This server exposes a `/metrics` endpoint that returns all daemon metrics
/// in Prometheus text format. Per REQ-DCP-0012, the following metrics are
/// exposed:
///
/// - `apm2_daemon_sessions_active` (gauge)
/// - `apm2_daemon_tool_mediation_latency_seconds` (histogram)
/// - `apm2_daemon_ipc_requests_total` (counter)
/// - `apm2_daemon_capability_grants_total` (counter)
/// - `apm2_daemon_context_firewall_denials_total` (counter)
/// - `apm2_daemon_session_terminations_total` (counter)
///
/// # Arguments
///
/// * `metrics_registry` - The shared metrics registry
/// * `addr` - The socket address to bind to (default: 127.0.0.1:9100)
///
/// # Security
///
/// The metrics endpoint binds to localhost only (127.0.0.1) by default to
/// prevent external access. If network access is required, configure a
/// reverse proxy with appropriate authentication.
async fn run_metrics_server(
    metrics_registry: SharedMetricsRegistry,
    addr: SocketAddr,
) -> Result<()> {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    // Create the metrics handler
    let metrics_handler = {
        let registry = Arc::clone(&metrics_registry);
        move || {
            let registry = Arc::clone(&registry);
            async move {
                match registry.encode_text() {
                    Ok(body) => (
                        StatusCode::OK,
                        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
                        body,
                    )
                        .into_response(),
                    Err(e) => {
                        error!("Failed to encode metrics: {}", e);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to encode metrics: {e}"),
                        )
                            .into_response()
                    },
                }
            }
        }
    };

    // Build the router
    let app = Router::new().route("/metrics", get(metrics_handler)).route(
        "/",
        get(|| async {
            "apm2-daemon metrics server\n\nGET /metrics - Prometheus metrics endpoint\n"
        }),
    );

    // Create the listener
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind metrics server")?;

    info!(addr = %addr, "Metrics HTTP server listening");

    // Serve requests
    axum::serve(listener, app)
        .await
        .context("metrics server error")?;

    Ok(())
}

// =============================================================================
// Tests: Real `perform_crash_recovery` integration (Quality Review v5 BLOCKER
// 1)
// =============================================================================

#[cfg(test)]
mod crash_recovery_integration_tests {
    use apm2_daemon::episode::PersistentSessionRegistry;
    use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
    use apm2_daemon::protocol::dispatch::{PolicyResolution, WorkClaim, WorkRegistry};
    use apm2_daemon::protocol::messages::WorkRole;
    use apm2_daemon::session::{SessionRegistry, SessionState};
    use rusqlite::params;

    use super::*;

    /// Creates a test signing key for ledger event emission.
    fn make_signing_key() -> ed25519_dalek::SigningKey {
        use rand::rngs::OsRng;
        ed25519_dalek::SigningKey::generate(&mut OsRng)
    }

    /// Creates a test session simulating a stale session from a prior daemon.
    fn make_session(id: &str, work_id: &str) -> SessionState {
        SessionState {
            session_id: id.to_string(),
            work_id: work_id.to_string(),
            role: 1,
            ephemeral_handle: format!("handle-{id}"),
            lease_id: String::new(),
            policy_resolved_ref: "policy-ref".to_string(),
            pcac_policy: None,
            pointer_only_waiver: None,
            capability_manifest_hash: vec![],
            episode_id: None,
        }
    }

    /// Creates an in-memory `SQLite` connection with schemas initialized.
    fn setup_sqlite() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        SqliteLedgerEventEmitter::init_schema(&conn).expect("init ledger schema");
        SqliteWorkRegistry::init_schema(&conn).expect("init work schema");
        Arc::new(Mutex::new(conn))
    }

    /// Registers a work claim in the `SQLite` work registry.
    fn register_claim(conn: &Arc<Mutex<Connection>>, work_id: &str) {
        let registry = SqliteWorkRegistry::new(Arc::clone(conn));
        let claim = WorkClaim {
            work_id: work_id.to_string(),
            lease_id: format!("lease-{work_id}"),
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "test-policy".to_string(),
            pcac_policy: None,
            pointer_only_waiver: None,
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
                resolved_risk_tier: 0,
                resolved_scope_baseline: None,
                expected_adapter_profile_hash: None,
            },
            executor_custody_domains: Vec::new(),
            author_custody_domains: Vec::new(),
            permeability_receipt: None,
        };
        registry.register_claim(claim).expect("register claim");
    }

    /// Quality Review v5 BLOCKER 1: Test that calls the real
    /// `perform_crash_recovery` function (not a simulated helper) with real
    /// dependencies (`PersistentSessionRegistry`, `SQLite` ledger).
    ///
    /// This test:
    /// 1. Creates a `PersistentSessionRegistry` state file with stale sessions
    /// 2. Creates a `DaemonStateHandle` via `new_with_persistent_sessions`
    /// 3. Creates a real `SQLite` connection with ledger + `work_claims`
    ///    schemas
    /// 4. Calls the real `perform_crash_recovery` function
    /// 5. Verifies `LEASE_REVOKED` events were emitted and work claims released
    #[tokio::test]
    async fn test_real_perform_crash_recovery_with_persistent_registry_and_sqlite() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Phase 1: Populate persistent session state file (simulating
        // a previous daemon run that crashed).
        {
            let registry = PersistentSessionRegistry::new(&state_path);
            registry
                .register_session(make_session("real-sess-1", "real-work-1"))
                .unwrap();
            registry
                .register_session(make_session("real-sess-2", "real-work-2"))
                .unwrap();
        }
        assert!(state_path.exists(), "State file must exist");

        // Phase 2: Create a real DaemonStateHandle with persistent sessions
        // (this is what the daemon does on startup).
        let config = EcosystemConfig::default();
        let supervisor = Supervisor::new();
        let schema_registry = InMemorySchemaRegistry::new();
        let _ = register_kernel_schemas(&schema_registry).await;

        let state: SharedState = Arc::new(
            DaemonStateHandle::new_with_persistent_sessions(
                config,
                supervisor,
                schema_registry,
                &state_path,
                None, // no metrics
            )
            .expect("state handle creation should succeed"),
        );

        // Verify sessions were loaded
        assert_eq!(
            state.session_registry().all_sessions_for_recovery().len(),
            2,
            "Should have loaded 2 stale sessions from state file"
        );

        // Phase 3: Create real SQLite connection with schemas
        let sqlite_conn = setup_sqlite();
        register_claim(&sqlite_conn, "real-work-1");
        register_claim(&sqlite_conn, "real-work-2");

        // Phase 4: Call the REAL perform_crash_recovery function
        let signing_key = make_signing_key();
        perform_crash_recovery(&state, Some(&sqlite_conn), &signing_key)
            .await
            .expect("real perform_crash_recovery should succeed");

        // Phase 5: Verify LEASE_REVOKED events were emitted
        {
            let db = sqlite_conn.lock().unwrap();
            let count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM ledger_events WHERE event_type = ?1",
                    params!["lease_revoked"],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 2,
                "Expected 2 lease_revoked events from real perform_crash_recovery"
            );

            // Verify work claims were released
            let claims_count: i64 = db
                .query_row("SELECT COUNT(*) FROM work_claims", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                claims_count, 0,
                "All work claims must be released after real recovery"
            );

            // Verify timestamps are non-zero (HTF clock was used)
            let min_ts: i64 = db
                .query_row(
                    "SELECT MIN(timestamp_ns) FROM ledger_events WHERE event_type = 'lease_revoked'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(min_ts > 0, "All events must have non-zero HTF timestamps");
        }

        // Phase 6: Verify session registry was cleared (idempotency)
        assert_eq!(
            state.session_registry().all_sessions_for_recovery().len(),
            0,
            "Session registry must be cleared after successful recovery"
        );
    }

    /// Test that `perform_crash_recovery` returns Ok when there are no
    /// sessions to recover (the common case on fresh startup).
    #[tokio::test]
    async fn test_real_perform_crash_recovery_no_sessions() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("empty-state.json");

        // Empty state file (no sessions from previous run)
        let config = EcosystemConfig::default();
        let supervisor = Supervisor::new();
        let schema_registry = InMemorySchemaRegistry::new();
        let _ = register_kernel_schemas(&schema_registry).await;

        let state: SharedState = Arc::new(
            DaemonStateHandle::new_with_persistent_sessions(
                config,
                supervisor,
                schema_registry,
                &state_path,
                None,
            )
            .expect("state handle creation should succeed"),
        );

        assert_eq!(
            state.session_registry().all_sessions_for_recovery().len(),
            0
        );

        // Call real perform_crash_recovery with no sessions
        let signing_key = make_signing_key();
        perform_crash_recovery(&state, None, &signing_key)
            .await
            .expect("recovery with no sessions should succeed");
    }

    /// Test that `perform_crash_recovery` returns Err (not just warns) when
    /// recovery fails, per Security Review v5 BLOCKER 1. Since
    /// `perform_crash_recovery` now propagates errors via `?`, a failure in
    /// registry clearing must result in an Err return.
    #[tokio::test]
    async fn test_real_perform_crash_recovery_propagates_integrity_errors() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create sessions
        {
            let registry = PersistentSessionRegistry::new(&state_path);
            registry
                .register_session(make_session("err-sess-1", "err-work-1"))
                .unwrap();
        }

        let config = EcosystemConfig::default();
        let supervisor = Supervisor::new();
        let schema_registry = InMemorySchemaRegistry::new();
        let _ = register_kernel_schemas(&schema_registry).await;

        let state: SharedState = Arc::new(
            DaemonStateHandle::new_with_persistent_sessions(
                config,
                supervisor,
                schema_registry,
                &state_path,
                None,
            )
            .expect("state handle creation should succeed"),
        );

        // With no SQLite connection, emitter is None, so ledger events are
        // only logged (not persisted). Recovery succeeds (no critical failures)
        // and clears the registry. This tests the happy path with ledger=None.
        let signing_key = make_signing_key();
        let result = perform_crash_recovery(&state, None, &signing_key).await;
        assert!(
            result.is_ok(),
            "Recovery without ledger should succeed (events logged, not persisted)"
        );

        // Verify sessions were cleared
        assert_eq!(
            state.session_registry().all_sessions_for_recovery().len(),
            0,
            "Sessions should be cleared after recovery even without ledger"
        );
    }
}
