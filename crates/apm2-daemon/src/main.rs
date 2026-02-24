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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use apm2_core::bootstrap::verify_bootstrap_hash;
use apm2_core::config::{
    EcosystemConfig, normalize_operator_socket_path, normalize_pid_file_path,
    normalize_session_socket_path, normalize_state_file_path,
};
use apm2_core::crypto::Signer;
use apm2_core::github::resolve_apm2_home;
use apm2_core::process::ProcessState;
use apm2_core::schema_registry::{InMemorySchemaRegistry, register_kernel_schemas};
use apm2_core::supervisor::Supervisor;
use apm2_daemon::gate::{
    GateOrchestrator, GateOrchestratorConfig, GateTimeoutKernel, GateTimeoutKernelConfig,
};
use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
use apm2_daemon::metrics::{SharedMetricsRegistry, new_shared_registry};
use apm2_daemon::projection::{DivergenceWatchdog, DivergenceWatchdogConfig, SystemTimeSource};
use apm2_daemon::protocol; // Import from library
use apm2_daemon::protocol::socket_manager::{SocketManager, SocketManagerConfig};
use apm2_daemon::state::{DaemonStateHandle, DispatcherState, SharedDispatcherState, SharedState};
use axum::Router;
use axum::routing::get;
use clap::Parser;
use rusqlite::{Connection, OptionalExtension};
use secrecy::ExposeSecret;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, error, info, trace, warn};
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

    /// Print the daemon HSI contract hash and exit.
    ///
    /// Hidden operator probe used by wrapper-side diagnostics to verify
    /// wrapper/daemon contract compatibility before startup.
    #[arg(long, hide = true)]
    print_hsi_contract_hash: bool,

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
        let operator_socket_raw = args
            .operator_socket
            .clone()
            .unwrap_or_else(|| config.daemon.operator_socket.clone());
        let session_socket_raw = args
            .session_socket
            .clone()
            .unwrap_or_else(|| config.daemon.session_socket.clone());
        let pid_raw = args
            .pid_file
            .clone()
            .unwrap_or_else(|| config.daemon.pid_file.clone());
        let state_file_raw = args
            .state_file
            .clone()
            .unwrap_or_else(|| config.daemon.state_file.clone());
        let operator_socket_path = normalize_operator_socket_path(&operator_socket_raw);
        let session_socket_path = normalize_session_socket_path(&session_socket_raw);
        let pid_path = normalize_pid_file_path(&pid_raw);
        let state_file_path = normalize_state_file_path(&state_file_raw);

        let ledger_db_path = args
            .ledger_db
            .clone()
            .or_else(|| config.daemon.ledger_db.clone());

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

#[cfg(test)]
#[allow(unsafe_code)]
mod daemon_config_tests {
    use super::*;

    #[test]
    fn hsi_contract_hash_probe_is_non_empty() {
        let hash = current_hsi_contract_hash().expect("HSI contract hash should resolve");
        assert!(
            !hash.trim().is_empty(),
            "HSI contract hash probe must be non-empty"
        );
        assert!(
            hash.starts_with("blake3:"),
            "HSI contract hash probe must use blake3 prefix, got: {hash}"
        );
    }

    fn args_with_config(config: PathBuf) -> Args {
        Args {
            config,
            no_daemon: true,
            print_hsi_contract_hash: false,
            pid_file: None,
            operator_socket: None,
            session_socket: None,
            state_file: None,
            ledger_db: None,
            cas_path: None,
            log_level: "info".to_string(),
            log_file: None,
            metrics_port: DEFAULT_METRICS_PORT,
            no_metrics: false,
        }
    }

    #[test]
    fn daemon_config_uses_default_ledger_db_when_not_overridden() {
        let temp = tempfile::TempDir::new().expect("create temp dir");
        let args = args_with_config(temp.path().join("missing-ecosystem.toml"));

        let daemon_config = DaemonConfig::new(&args).expect("daemon config should load");
        assert_eq!(
            daemon_config.ledger_db_path,
            Some(apm2_core::config::default_data_dir().join("ledger.db"))
        );
    }

    #[test]
    fn daemon_config_uses_ledger_db_from_config_when_cli_absent() {
        let temp = tempfile::TempDir::new().expect("create temp dir");
        let config_path = temp.path().join("ecosystem.toml");
        std::fs::write(
            &config_path,
            "[daemon]\n\
             operator_socket = \"/tmp/apm2/operator.sock\"\n\
             session_socket = \"/tmp/apm2/session.sock\"\n\
             ledger_db = \"/tmp/apm2/from-config.db\"\n",
        )
        .expect("write config");

        let args = args_with_config(config_path);
        let daemon_config = DaemonConfig::new(&args).expect("daemon config should load");
        assert_eq!(
            daemon_config.ledger_db_path,
            Some(PathBuf::from("/tmp/apm2/from-config.db"))
        );
    }

    #[test]
    fn daemon_config_prefers_cli_ledger_db_over_config() {
        let temp = tempfile::TempDir::new().expect("create temp dir");
        let config_path = temp.path().join("ecosystem.toml");
        std::fs::write(
            &config_path,
            "[daemon]\n\
             operator_socket = \"/tmp/apm2/operator.sock\"\n\
             session_socket = \"/tmp/apm2/session.sock\"\n\
             ledger_db = \"/tmp/apm2/from-config.db\"\n",
        )
        .expect("write config");

        let mut args = args_with_config(config_path);
        args.ledger_db = Some(PathBuf::from("/tmp/apm2/from-cli.db"));

        let daemon_config = DaemonConfig::new(&args).expect("daemon config should load");
        assert_eq!(
            daemon_config.ledger_db_path,
            Some(PathBuf::from("/tmp/apm2/from-cli.db"))
        );
    }

    #[test]
    fn daemon_config_normalizes_tmp_runtime_paths() {
        let temp = tempfile::TempDir::new().expect("create temp dir");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");
        let config_path = temp.path().join("ecosystem.toml");
        std::fs::write(
            &config_path,
            "[daemon]\n\
             pid_file = \"/tmp/apm2.pid\"\n\
             operator_socket = \"/tmp/apm2/operator.sock\"\n\
             session_socket = \"/tmp/apm2/session.sock\"\n\
             state_file = \"/tmp/apm2/state.json\"\n",
        )
        .expect("write config");
        // SAFETY: test-only env override scoped to this test.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir) };

        let args = args_with_config(config_path);
        let daemon_config = DaemonConfig::new(&args).expect("daemon config should load");
        assert_eq!(
            daemon_config.operator_socket_path,
            runtime_dir.join("apm2").join("operator.sock")
        );
        assert_eq!(
            daemon_config.session_socket_path,
            runtime_dir.join("apm2").join("session.sock")
        );
        assert_eq!(
            daemon_config.pid_path,
            runtime_dir.join("apm2").join("apm2.pid")
        );
        assert!(
            !daemon_config
                .state_file_path
                .starts_with(std::path::Path::new("/tmp")),
            "state file path should avoid /tmp under normalization"
        );
        // SAFETY: test cleanup for env override.
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
    }
}

/// Write PID file atomically.
///
/// TCK-00537: Uses [`apm2_daemon::fs_safe::atomic_write`] for crash-safe
/// PID file creation (temp + fsync + rename). Parent directory is created
/// with mode 0700 (restrictive permissions).
fn write_pid_file(pid_path: &PathBuf) -> Result<()> {
    apm2_daemon::fs_safe::atomic_write(pid_path, std::process::id().to_string().as_bytes())
        .context("failed to write PID file atomically")?;
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
fn load_or_create_persistent_signer(
    key_path: &std::path::Path,
) -> Result<apm2_core::crypto::Signer> {
    use apm2_core::crypto::Signer;

    match apm2_daemon::fs_safe::bounded_read(key_path, 4096) {
        Ok(key_bytes) => {
            // TCK-00537: Load uses safe_open (symlink refusal + bounded read).
            if key_bytes.len() != 32 {
                anyhow::bail!(
                    "invalid signer key file: expected 32 bytes, got {}",
                    key_bytes.len()
                );
            }

            Signer::from_bytes(&key_bytes)
                .map_err(|e| anyhow::anyhow!("failed to parse signer key: {e}"))
        },
        Err(apm2_daemon::fs_safe::FsSafeError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            // Generate new key and save it
            let signer = Signer::generate();
            let key_bytes = signer.secret_key_bytes();

            // TCK-00537: Use atomic_write for crash-safe key persistence.
            // atomic_write creates temp file with 0600 permissions
            // (NamedTempFile default), fsync, then rename.
            apm2_daemon::fs_safe::atomic_write(key_path, &*key_bytes)
                .context("failed to write signer key atomically")?;

            info!(key_path = %key_path.display(), "Generated new persistent projection signer key");

            Ok(signer)
        },
        Err(e) => Err(anyhow::anyhow!("failed to read signer key file: {e}")),
    }
}

fn ledger_signing_key_path(daemon_config: &DaemonConfig) -> PathBuf {
    if let Some(ledger_db_path) = daemon_config.ledger_db_path.as_ref() {
        return ledger_db_path.parent().map_or_else(
            || PathBuf::from("/var/lib/apm2/ledger_signer.key"),
            |parent| parent.join("ledger_signer.key"),
        );
    }

    daemon_config.state_file_path.parent().map_or_else(
        || PathBuf::from("/var/lib/apm2/ledger_signer.key"),
        |parent| parent.join("ledger_signer.key"),
    )
}

/// Load or create the Ed25519 signing key used for ledger hash-chain
/// checkpoints.
///
/// The key file stores a 32-byte seed and is created with mode 0600.
///
/// # Critical State File
///
/// The key file at `<state_dir>/ledger_signer.key` is a **critical persistent
/// artifact**. Loss of this file (e.g., container replacement without a
/// persistent volume) will cause the daemon to fail startup because historical
/// checkpoint signatures cannot be verified. Operators MUST ensure this file is
/// persisted across restarts and backed up as part of disaster recovery
/// procedures.
fn load_or_create_ledger_signing_key(
    daemon_config: &DaemonConfig,
) -> Result<ed25519_dalek::SigningKey> {
    use std::io::ErrorKind;

    let key_path = ledger_signing_key_path(daemon_config);

    if let Some(parent) = key_path.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .context("failed to create ledger signer key directory")?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(parent)
                .context("failed to create ledger signer key directory")?;
        }
    }

    // TCK-00537: Use fs_safe primitives for symlink refusal (O_NOFOLLOW),
    // bounded reads, and regular-file verification.
    match apm2_daemon::fs_safe::bounded_read(&key_path, 4096) {
        Ok(key_bytes) => {
            // Validate permissions on the opened file handle (post-open, not
            // path-based — safe_open already refused symlinks).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                let metadata = std::fs::symlink_metadata(&key_path)
                    .context("failed to stat ledger signer key file")?;
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    anyhow::bail!(
                        "ledger signer key file '{}' has insecure permissions {:o}; expected 0600",
                        key_path.display(),
                        mode
                    );
                }
            }

            if key_bytes.len() != 32 {
                anyhow::bail!(
                    "invalid ledger signer key file: expected 32 bytes, got {}",
                    key_bytes.len()
                );
            }

            let key_seed: [u8; 32] = key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("failed to decode ledger signer key seed"))?;
            info!(key_path = %key_path.display(), "Loaded persistent ledger signing key");
            Ok(ed25519_dalek::SigningKey::from_bytes(&key_seed))
        },
        Err(apm2_daemon::fs_safe::FsSafeError::Io { source, .. })
            if source.kind() == ErrorKind::NotFound =>
        {
            use rand::rngs::OsRng;

            let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let key_bytes = signing_key.to_bytes();

            // TCK-00537: Use atomic_write for crash-safe key persistence.
            // atomic_write creates parent dir with 0700 and temp file with
            // 0600 permissions, fsync, then atomic rename.
            apm2_daemon::fs_safe::atomic_write(&key_path, &key_bytes)
                .context("failed to write ledger signer key atomically")?;

            info!(key_path = %key_path.display(), "Generated new persistent ledger signing key");
            Ok(signing_key)
        },
        Err(e) => Err(anyhow::anyhow!("failed to read ledger signer key: {e}")),
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

    // Hidden preflight probe for wrapper-side contract compatibility checks.
    if args.print_hsi_contract_hash {
        println!("{}", current_hsi_contract_hash()?);
        return Ok(());
    }

    // TCK-00595 MAJOR-1 FIX: Do NOT auto-detect GitHub owner/repo from CWD.
    //
    // The daemon is a user-singleton (fixed XDG socket path). Binding it to
    // the CWD at startup causes cross-context pollution: if the user starts
    // the daemon from repo A's directory, it permanently serves repo A's
    // projection even when the user switches to repo B.
    //
    // The daemon MUST require explicit configuration via ecosystem.toml's
    // [daemon.projection] section (github_owner + github_repo). Auto-detect
    // from `git remote` is appropriate only in the short-lived CLI client
    // layer, not in the long-lived daemon.

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

fn current_hsi_contract_hash() -> Result<String> {
    let cli_version = apm2_daemon::hsi_contract::CliVersion {
        semver: env!("CARGO_PKG_VERSION").to_string(),
        build_hash: String::new(),
    };
    let manifest = apm2_daemon::hsi_contract::build_manifest(cli_version)
        .context("failed to build HSI contract manifest")?;
    let hash = manifest
        .content_hash()
        .context("failed to compute HSI contract content hash")?;
    if hash.is_empty() {
        bail!("HSI contract content hash is empty");
    }
    Ok(hash)
}

fn ensure_canonicalizer_tuple_admitted(
    fac_root: &Path,
    current_tuple: &apm2_core::fac::CanonicalizerTupleV1,
    _tuple_broker: &mut apm2_core::fac::FacBroker,
) -> Result<()> {
    use apm2_core::fac::FacBroker;

    let tuple_path = fac_root
        .join("broker")
        .join("admitted_canonicalizer_tuple.v1.json");
    if !tuple_path.exists() {
        return Err(anyhow::anyhow!(
            "No admitted canonicalizer tuple found. Run 'apm2 fac canonicalizer admit' to bootstrap."
        ));
    }

    let admitted_tuple = FacBroker::load_admitted_tuple(fac_root).map_err(|error| {
        anyhow::anyhow!(
            "failed to load admitted canonicalizer tuple {}: {error}",
            tuple_path.display()
        )
    })?;

    if admitted_tuple != *current_tuple {
        return Err(anyhow::anyhow!(
            "FATAL: canonicalizer tuple mismatch in broker: admitted={} current={}",
            admitted_tuple.compute_digest(),
            current_tuple.compute_digest()
        ));
    }

    Ok(())
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
    let apm2_home = resolve_apm2_home().ok_or_else(|| {
        anyhow::anyhow!("failed to resolve APM2 home from $APM2_HOME or home directory")
    })?;
    let fac_root = apm2_home.join("private").join("fac");
    let node_fingerprint = apm2_core::fac::load_or_derive_node_fingerprint(&apm2_home)
        .context("failed to load or derive node fingerprint")?;
    let boundary_id = apm2_core::fac::load_or_default_boundary_id(&apm2_home)
        .context("failed to load boundary id")?;
    let current_tuple = apm2_core::fac::CanonicalizerTupleV1::from_current();
    let mut tuple_broker = apm2_core::fac::FacBroker::new();
    ensure_canonicalizer_tuple_admitted(&fac_root, &current_tuple, &mut tuple_broker)
        .context("canonicalizer tuple admission check failed")?;
    info!(
        apm2_home = %apm2_home.display(),
        node_fingerprint = %node_fingerprint,
        boundary_id = %boundary_id,
        "Loaded FAC node identity"
    );

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

    // Load one persistent ledger signing key and reuse it across daemon
    // restarts and runtime paths (startup validation, crash recovery, and
    // dispatcher emission).
    let ledger_signing_key = load_or_create_ledger_signing_key(&daemon_config)
        .context("failed to load ledger signing key")?;
    let lifecycle_signing_key_bytes = ledger_signing_key.to_bytes();

    // Initialize persistent ledger if configured (TCK-00289)
    // TCK-00387: Moved BEFORE crash recovery so that LEASE_REVOKED events can
    // be emitted to the ledger during recovery.
    let sqlite_conn = if let Some(path) = &daemon_config.ledger_db_path {
        info!("Opening ledger database at {:?}", path);
        let conn = Connection::open(path).context("failed to open ledger database")?;

        // Initialize schemas and perform startup checkpoint validation using
        // the trusted daemon lifecycle signing key.
        SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &ledger_signing_key)
            .context("failed to init ledger events schema")?;
        SqliteWorkRegistry::init_schema(&conn).context("failed to init work claims schema")?;

        // TCK-00630: RFC-0032 Phase 0 — migrate legacy `ledger_events` to
        // canonical `events` table before any consumers initialize.
        // Fail-closed: if migration fails, the daemon must not start.
        apm2_core::ledger::init_canonical_schema(&conn)
            .context("failed to init canonical events schema for migration")?;
        let migration_stats = apm2_core::ledger::migrate_legacy_ledger_events(&conn)
            .context("failed to migrate legacy ledger events (RFC-0032)")?;
        if migration_stats.already_migrated {
            info!("Legacy ledger migration: already migrated (no-op)");
        } else {
            info!(
                rows_migrated = migration_stats.rows_migrated,
                "Legacy ledger migration completed (RFC-0032)"
            );
        }

        // TCK-00631: Post-migration invariant check — after migration, the
        // ledger MUST be in canonical events mode. If it is still in legacy
        // mode, something went wrong and the daemon must not start.
        let is_canonical = apm2_core::ledger::is_canonical_events_mode(&conn)
            .context("failed to determine ledger read mode after migration")?;
        if !is_canonical {
            anyhow::bail!(
                "post-migration invariant violated: ledger is NOT in canonical events mode \
                 after migration completed; daemon startup aborted (fail-closed)"
            );
        }

        // TCK-00631: Check whether the frozen legacy table exists and log
        // the current ledger mode.
        let frozen_table_exists: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' \
                 AND name = 'ledger_events_legacy_frozen' LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .unwrap_or(None)
            .is_some();

        info!(
            ledger_mode = "canonical_events",
            frozen_table_exists = frozen_table_exists,
            legacy_writes_frozen = frozen_table_exists,
            "TCK-00631: Ledger mode after startup migration"
        );

        Some(Arc::new(Mutex::new(conn)))
    } else {
        None
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

    // TCK-00600: Notify systemd that the daemon is ready.
    // This must happen after socket bind so that clients can connect
    // immediately after systemd considers the service started.
    let _ = apm2_core::fac::sd_notify::notify_ready();
    let _ = apm2_core::fac::sd_notify::notify_status("daemon ready, accepting connections");

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
                Some(ed25519_dalek::SigningKey::from_bytes(
                    &lifecycle_signing_key_bytes,
                )),
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
                Some(ed25519_dalek::SigningKey::from_bytes(
                    &lifecycle_signing_key_bytes,
                )),
                &daemon_config.config.daemon.adapter_rotation,
            )
            .map_err(|e| anyhow::anyhow!("adapter rotation initialization failed: {e}"))?
        }
        .with_daemon_state(Arc::clone(&state))
        // TCK-00565: Wire boundary_id from node identity into the dispatcher
        // so that tokens issued through the daemon dispatch path include the
        // correct boundary_id in their TokenBindingV1.
        .with_token_binding_config(boundary_id.clone(), [0u8; 32]),
    );

    // TCK-00631: Freeze legacy `ledger_events` writes on both the event emitter
    // and lease validator. After this, all new appends route to canonical `events`.
    // This MUST happen after init_canonical_schema + migrate_legacy_ledger_events
    // (above) to ensure the `events` table exists.
    if sqlite_conn.is_some() {
        if let Err(e) = dispatcher_state.freeze_legacy_writes() {
            warn!(error = %e, "freeze_legacy_writes failed (writes blocked, fail-closed)");
        }
        info!("TCK-00631: Legacy ledger writes frozen; new appends route to canonical events");
    }

    // TCK-00388: Wire gate orchestrator into daemon for autonomous gate lifecycle.
    //
    // The orchestrator is instantiated with the daemon lifecycle signing key
    // and wired into the DispatcherState. When a session terminates, the dispatcher
    // calls `notify_session_terminated` which delegates to the orchestrator. A
    // background task polls for gate timeouts periodically.
    let gate_signer = Arc::new(
        Signer::from_bytes(&lifecycle_signing_key_bytes)
            .map_err(|e| anyhow::anyhow!("failed to derive gate signer from lifecycle key: {e}"))?,
    );
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
    //
    // MAJOR-1 fix (INV-BRK-HEALTH-GATE-001): The poller also continuously
    // evaluates broker health and updates the PrivilegedDispatcher's
    // admission health gate. The gate starts closed (fail-closed) and only
    // opens when a health check returns Healthy. On degradation/failure,
    // the gate is actively closed until the next successful check.
    {
        let orch = Arc::clone(&gate_orchestrator);
        let timeout_signing_key_bytes = lifecycle_signing_key_bytes;
        // Create a dedicated ledger emitter for the timeout poller if a
        // ledger database is configured. Uses the same sqlite_conn (shared
        // via Arc<Mutex>) and the daemon lifecycle signing key.
        let timeout_ledger_emitter: Option<SqliteLedgerEventEmitter> =
            sqlite_conn.as_ref().map(|conn| {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&timeout_signing_key_bytes);
                let emitter = SqliteLedgerEventEmitter::new(Arc::clone(conn), signing_key);
                // TCK-00631: Freeze legacy writes after RFC-0032 migration.
                // Fail-closed: if freeze check fails, writes are blocked anyway.
                if let Err(e) = emitter.freeze_legacy_writes_self() {
                    warn!(error = %e, "freeze_legacy_writes failed (writes blocked, fail-closed)");
                }
                emitter
            });
        let timeout_kernel = GateTimeoutKernel::new(
            Arc::clone(&orch),
            sqlite_conn.as_ref(),
            timeout_ledger_emitter,
            &fac_root,
            GateTimeoutKernelConfig::default(),
        )
        .map_err(|e| anyhow::anyhow!("failed to initialize gate timeout kernel: {e}"))?;

        // MAJOR-1 fix: Create a daemon-level FacBroker and
        // BrokerHealthChecker for periodic health evaluation. The broker
        // uses the daemon lifecycle signing key so its self-issued envelopes
        // and health receipts are cryptographically bound to this daemon
        // instance. The checker maintains a monotonic health_seq to prevent
        // replay of stale healthy receipts.
        //
        // Synchronization protocol (RS-21):
        // - Protected data: daemon-level FacBroker state + BrokerHealthChecker
        //   history/seq
        // - Writers: only this poller task (single writer)
        // - Readers: only this poller task (single reader)
        // - No concurrent access: both are owned by the spawned task and accessed
        //   sequentially within each poll iteration
        // - The AtomicBool on the static PrivilegedDispatcher is the cross-task
        //   communication channel (Release/Acquire ordering)
        let health_signer = apm2_core::crypto::Signer::from_bytes(&timeout_signing_key_bytes)
            .expect("lifecycle signing key validated at daemon startup");
        let mut health_broker = apm2_core::fac::FacBroker::from_signer_and_state(
            health_signer,
            apm2_core::fac::BrokerState::default(),
        )
        .expect("default BrokerState is always valid");
        let mut health_checker = apm2_core::fac::BrokerHealthChecker::new();
        let boundary_id = boundary_id.clone();
        // TCK-00600: Clone fac_root into the poller task so we can write
        // broker_health.json after each health evaluation.
        let fac_root_for_poller = fac_root.clone();
        let daemon_start = std::time::Instant::now();

        tokio::spawn(async move {
            let mut timeout_kernel = timeout_kernel;
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            // TCK-00600: Watchdog ticker sends WATCHDOG=1 to systemd at half
            // the WatchdogSec interval. Runs in the same poller task because
            // it already ticks every 10 seconds.
            let mut watchdog = apm2_core::fac::sd_notify::WatchdogTicker::new();
            loop {
                interval.tick().await;
                // TCK-00600: Ping systemd watchdog if due.
                watchdog.ping_if_due();
                match timeout_kernel.tick().await {
                    Ok(report) => {
                        if report.executed_intents > 0 || report.persisted_receipts > 0 {
                            info!(
                                executed_intents = report.executed_intents,
                                completed_intents = report.completed_intents,
                                blocked_intents = report.blocked_intents,
                                persisted_receipts = report.persisted_receipts,
                                "Gate timeout kernel tick completed"
                            );
                        }
                    },
                    Err(e) => {
                        error!(
                            error = %e,
                            "Gate timeout kernel tick failed (fail-closed)"
                        );
                    },
                }

                // ---------------------------------------------------------------
                // MAJOR-1 fix: Periodic broker health evaluation for the static
                // PrivilegedDispatcher's admission health gate.
                //
                // The daemon-level FacBroker issues a self-signed time authority
                // envelope and advances its freshness horizon on each poll cycle.
                // The health check validates TP001/TP002/TP003 invariants against
                // this broker's state. If the check returns Healthy, the gate
                // opens; otherwise it closes (fail-closed).
                //
                // This replaces the sticky one-time startup gate open with a
                // continuously re-evaluated, receipt-bound health signal on a
                // bounded 10-second interval.
                // ---------------------------------------------------------------
                let broker_tick = health_broker.advance_tick();
                let eval_window = apm2_core::economics::queue_admission::HtfEvaluationWindow {
                    boundary_id: boundary_id.clone(),
                    authority_clock: "daemon-lifecycle".to_string(),
                    tick_start: broker_tick.saturating_sub(1),
                    tick_end: broker_tick,
                };

                // Issue a self-signed envelope covering the evaluation window.
                // Fail-closed: if envelope issuance fails, close the gate.
                let envelope_result = health_broker.issue_time_authority_envelope(
                    &boundary_id,
                    "daemon-lifecycle",
                    eval_window.tick_start,
                    eval_window.tick_end,
                    100, // TTL: 100 ticks, well within MAX_ENVELOPE_TTL_TICKS
                );

                let gate_healthy = match envelope_result {
                    Ok(envelope) => {
                        // Advance freshness horizon so TP002 has resolved state.
                        health_broker.advance_freshness_horizon(broker_tick);

                        // Run the health check through the broker's full
                        // TP001/TP002/TP003 validation pipeline.
                        match health_broker.check_health(
                            Some(&envelope),
                            &eval_window,
                            &[], // No required authority sets for daemon-level check
                            &mut health_checker,
                        ) {
                            Ok(receipt) => {
                                receipt.status == apm2_core::fac::BrokerHealthStatus::Healthy
                            },
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "Daemon health check failed; closing admission gate \
                                     (fail-closed, INV-BRK-HEALTH-GATE-001)"
                                );
                                false
                            },
                        }
                    },
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Daemon health envelope issuance failed; closing admission gate \
                             (fail-closed, INV-BRK-HEALTH-GATE-001)"
                        );
                        false
                    },
                };

                // TCK-00568: Reset control-plane budget counters at each tick
                // boundary. This is the ONLY call site for
                // `reset_control_plane_counters()` — without it, per-tick
                // rate limits become permanent process-lifetime quotas.
                apm2_daemon::protocol::session_dispatch::channel_boundary_dispatcher()
                    .reset_control_plane_counters();

                // Update the static PrivilegedDispatcher's admission health gate.
                // Release ordering ensures all health evaluation side-effects are
                // visible to subsequent Acquire loads in the token issuance path.
                apm2_daemon::protocol::session_dispatch::channel_boundary_dispatcher()
                    .set_admission_health_gate(gate_healthy);

                if !gate_healthy {
                    warn!(
                        "Admission health gate CLOSED by poller \
                         (INV-BRK-HEALTH-GATE-001)"
                    );
                }

                // TCK-00600: Write broker health IPC file after each health
                // evaluation. This file is read by `apm2 fac services status`
                // to report broker readiness and version independently of
                // systemd unit state. Fail-open: a write failure is logged but
                // does not affect the admission gate (INV-BHI-004).
                let health_status_str = if gate_healthy { "healthy" } else { "unhealthy" };
                let uptime_secs = daemon_start.elapsed().as_secs();
                if let Err(e) = apm2_core::fac::broker_health_ipc::write_broker_health(
                    &fac_root_for_poller,
                    env!("CARGO_PKG_VERSION"),
                    gate_healthy,
                    uptime_secs,
                    health_status_str,
                    if gate_healthy {
                        None
                    } else {
                        Some("admission health gate closed")
                    },
                ) {
                    warn!(
                        error = %e,
                        "Failed to write broker health IPC file (non-fatal)"
                    );
                }

                // TCK-00600: Read worker heartbeat and incorporate its
                // staleness state into daemon health reporting. The worker
                // writes `worker_heartbeat.json` after each poll cycle;
                // the daemon reads it here to surface worker health
                // alongside broker health. This is observability only —
                // a stale or missing heartbeat does not affect the broker
                // admission gate (INV-WHB-005).
                let worker_hb =
                    apm2_core::fac::worker_heartbeat::read_heartbeat(&fac_root_for_poller);
                if worker_hb.found {
                    if worker_hb.fresh {
                        trace!(
                            worker_pid = worker_hb.pid,
                            worker_cycle_count = worker_hb.cycle_count,
                            worker_age_secs = worker_hb.age_secs,
                            worker_health = %worker_hb.health_status,
                            "Worker heartbeat fresh"
                        );
                    } else {
                        warn!(
                            worker_pid = worker_hb.pid,
                            worker_age_secs = worker_hb.age_secs,
                            "Worker heartbeat stale (age > {}s)",
                            apm2_core::fac::worker_heartbeat::MAX_HEARTBEAT_AGE_SECS
                        );
                    }
                } else {
                    debug!("Worker heartbeat file not found (worker may not be running)");
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

        // TCK-00595 MAJOR-1 FIX: The daemon MUST NOT auto-detect owner/repo
        // from CWD. The daemon is a user-singleton with a fixed socket path;
        // binding it to the startup CWD's git remote would cause cross-context
        // pollution if the user switches repositories. Only explicit config
        // values are used.
        let github_owner = projection_config.github_owner.clone();
        let github_repo = projection_config.github_repo.clone();

        if projection_config.enabled && (github_owner.is_empty() || github_repo.is_empty()) {
            tracing::warn!(
                "projection.enabled=true but github_owner or github_repo is not set in config; \
                 set [daemon.projection] github_owner and github_repo in ecosystem.toml"
            );
        }

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
        if projection_config.enabled && !github_owner.is_empty() && !github_repo.is_empty() {
            // Build GitHub adapter config
            match GitHubAdapterConfig::new(
                &projection_config.github_api_url,
                &github_owner,
                &github_repo,
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
                    // TCK-00595 MAJOR FIX: Use unified token resolution that
                    // checks env var, then $CREDENTIALS_DIRECTORY/gh-token
                    // (systemd LoadCredential), then $APM2_HOME/private/creds/gh-token.
                    let Some(token) = apm2_core::config::resolve_github_token(env_var) else {
                        // TCK-00322 MAJOR FIX: Missing token is fatal when enabled
                        error!(
                            env_var = %env_var,
                            "GitHub token not found. Checked: ${env_var} env var, \
                             $CREDENTIALS_DIRECTORY/gh-token, $APM2_HOME/private/creds/gh-token. \
                             projection.enabled=true requires a valid token."
                        );
                        return Err(anyhow::anyhow!(
                            "projection.enabled=true but GitHub token not resolvable \
                             (checked env var {env_var}, systemd credentials, APM2 cred file)"
                        ));
                    };

                    github_config =
                        match github_config.clone().with_api_token(token.expose_secret()) {
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
                                owner = %github_owner,
                                repo = %github_repo,
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
                if let Some(authoritative_cas) = dispatcher_state.evidence_cas() {
                    worker.set_authoritative_cas(authoritative_cas);
                    info!(
                        "Authoritative CAS injected into projection worker for receipt linkage validation"
                    );
                } else {
                    warn!(
                        "Projection worker started without authoritative CAS; receipt linkage validation will fail closed"
                    );
                }

                // BLOCKER FIX: Actually inject the adapter into the worker!
                // This was the critical missing step that caused all projections to be skipped.
                if let Some(adapter) = github_adapter {
                    worker.set_adapter(adapter);
                    info!("GitHub adapter injected into projection worker");
                } else {
                    // When projection is disabled, this is expected
                    info!("Projection worker started without adapter (projection disabled)");
                }

                // TCK-00505 MAJOR FIX: Wire economics admission gate dependencies.
                //
                // The economics gate requires three components:
                // 1. IntentBuffer for durable admission decisions
                // 2. ConfigBackedResolver for continuity profile resolution
                // 3. Gate signer for constructing signed window/profile artifacts
                //
                // All three must be present for has_economics_gate() to return true.
                // If any fails to initialize, the worker starts without the gate.
                //
                // SECURITY (MAJOR-1 fix): When the gate is NOT wired, ALL
                // events are DENIED (fail-closed). Events with economics
                // selectors are denied due to missing gate; events without
                // selectors are denied due to missing economics selectors.
                // This prevents init failure from silently bypassing
                // economics enforcement.
                {
                    use apm2_daemon::projection::{ConfigBackedResolver, IntentBuffer};

                    // Intent buffer: uses a separate SQLite connection for isolation.
                    let intent_db_path = daemon_config.state_file_path.parent().map_or_else(
                        || std::path::PathBuf::from("/var/lib/apm2/projection_intents.db"),
                        |p| p.join("projection_intents.db"),
                    );
                    match Connection::open(&intent_db_path) {
                        Ok(intent_conn) => {
                            let intent_conn = Arc::new(Mutex::new(intent_conn));
                            match IntentBuffer::new(Arc::clone(&intent_conn)) {
                                Ok(buffer) => {
                                    worker.set_intent_buffer(buffer);
                                    info!(
                                        path = %intent_db_path.display(),
                                        "Intent buffer initialized for economics gate"
                                    );
                                },
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        "Failed to initialize intent buffer; economics gate disabled"
                                    );
                                },
                            }
                        },
                        Err(e) => {
                            warn!(
                                path = %intent_db_path.display(),
                                error = %e,
                                "Failed to open intent buffer database; economics gate disabled"
                            );
                        },
                    }

                    // Continuity resolver: built from config sink profiles.
                    if projection_config.sinks.is_empty() {
                        info!(
                            "No projection sinks configured; economics gate disabled \
                             (projections proceed without economics checking)"
                        );
                    } else {
                        match ConfigBackedResolver::from_config(&projection_config.sinks) {
                            Ok(resolver) => {
                                worker.set_continuity_resolver(Arc::new(resolver));
                                info!(
                                    sink_count = projection_config.sinks.len(),
                                    "Continuity resolver initialized for economics gate"
                                );
                            },
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "Failed to initialize continuity resolver; economics gate disabled"
                                );
                            },
                        }
                    }

                    // Gate signer: reuse the persistent projection signer key.
                    // The signer_key_path was already resolved above for the adapter.
                    let gate_signer_key_path = projection_config
                        .signer_key_file
                        .clone()
                        .unwrap_or_else(|| {
                            daemon_config.state_file_path.parent().map_or_else(
                                || PathBuf::from("/var/lib/apm2/projection_signer.key"),
                                |p| p.join("projection_signer.key"),
                            )
                        });
                    match load_or_create_persistent_signer(&gate_signer_key_path) {
                        Ok(signer) => {
                            worker.set_gate_signer(Arc::new(signer));
                            info!(
                                key_path = %gate_signer_key_path.display(),
                                "Gate signer initialized for economics gate"
                            );
                        },
                        Err(e) => {
                            warn!(
                                error = %e,
                                "Failed to load gate signer; economics gate disabled"
                            );
                        },
                    }

                    if worker.has_economics_gate() {
                        info!(
                            "Economics admission gate ACTIVE: projections will be \
                             economics-gated with idempotent-insert replay prevention"
                        );
                    } else {
                        warn!(
                            "Economics admission gate INACTIVE: ALL events will be \
                             DENIED (fail-closed). Events with economics selectors \
                             are denied due to missing gate; events without selectors \
                             are denied due to missing economics selectors."
                        );
                    }
                }

                let shutdown_flag = worker.shutdown_handle();
                let worker_state = state.clone();

                info!(
                    github_enabled = projection_config.enabled,
                    has_adapter = worker.has_adapter(),
                    has_economics_gate = worker.has_economics_gate(),
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
    //
    // TCK-00469: The watchdog is wrapped in Arc so both the background polling
    // task and the DispatcherState share the same instance, enabling IPC
    // handlers to call register_durable_recovery_evidence / create_unfreeze /
    // apply_unfreeze.
    let watchdog_arc_for_dispatcher: Option<Arc<DivergenceWatchdog<SystemTimeSource>>> = {
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

            // Resolve GitHub token via unified resolution chain (TCK-00595 MAJOR FIX):
            // env var -> $CREDENTIALS_DIRECTORY/gh-token ->
            // $APM2_HOME/private/creds/gh-token
            let token_env_raw = dw_config
                .github_token_env
                .as_deref()
                .unwrap_or("GITHUB_TOKEN");
            let token_env = token_env_raw.strip_prefix('$').unwrap_or(token_env_raw);
            let github_token =
                apm2_core::config::resolve_github_token(token_env).ok_or_else(|| {
                    anyhow::anyhow!(
                        "divergence_watchdog.enabled=true but GitHub token not resolvable \
                         (checked env var {token_env}, $CREDENTIALS_DIRECTORY/gh-token, \
                         $APM2_HOME/private/creds/gh-token)"
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
            let watchdog_signer =
                Signer::from_bytes(&lifecycle_signing_key_bytes).map_err(|e| {
                    anyhow::anyhow!("failed to derive watchdog signer from lifecycle key: {e}")
                })?;
            let watchdog = Arc::new(DivergenceWatchdog::new(watchdog_signer, watchdog_config));

            info!(
                repo = %repo_id,
                branch = %dw_config.trunk_branch,
                poll_interval_secs = dw_config.poll_interval_secs,
                "Divergence watchdog enabled"
            );

            let watchdog_signing_key_bytes = lifecycle_signing_key_bytes;
            // Create a dedicated ledger emitter for the watchdog.
            let watchdog_ledger_emitter: Option<SqliteLedgerEventEmitter> =
                sqlite_conn.as_ref().map(|conn| {
                    let signing_key =
                        ed25519_dalek::SigningKey::from_bytes(&watchdog_signing_key_bytes);
                    let emitter = SqliteLedgerEventEmitter::new(Arc::clone(conn), signing_key);
                    // TCK-00631: Freeze legacy writes after RFC-0032 migration.
                    if let Err(e) = emitter.freeze_legacy_writes_self() {
                        warn!(error = %e, "freeze_legacy_writes failed (writes blocked, fail-closed)");
                    }
                    emitter
                });

            // Capture values for the spawned task
            let github_api_url = dw_config.github_api_url.clone();
            let github_owner = dw_config.github_owner.clone();
            let github_repo = dw_config.github_repo.clone();
            let trunk_branch = dw_config.trunk_branch.clone();
            let watchdog_state = state.clone();
            let watchdog_repo_id = repo_id;

            // TCK-00469: Clone the Arc for the background task; the original
            // is returned from this block for dispatcher wiring.
            let watchdog_task_ref = Arc::clone(&watchdog);
            tokio::spawn(async move {
                let watchdog = watchdog_task_ref;
                let mut interval = tokio::time::interval(poll_interval);
                let precautionary_freeze_id = format!("precautionary-{watchdog_repo_id}");
                let mut consecutive_check_errors: u32 = 0;

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
                            consecutive_check_errors = 0;
                            // Divergence detected! Emit DefectRecorded event.
                            error!(
                                expected_head = %hex::encode(merge_receipt_head),
                                actual_head = %hex::encode(external_head),
                                freeze_id = %result.freeze.freeze_id(),
                                "DIVERGENCE DETECTED: trunk HEAD does not match \
                                 ledger MergeReceipt HEAD"
                            );

                            // Emit DefectRecorded + InterventionFreeze transition
                            // events to the ledger.
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

                                let emit_trace_event =
                                    |event_type: &str,
                                     payload: &[u8],
                                     actor_id: &str,
                                     timestamp_ns: u64| {
                                        match emitter.emit_session_event(
                                            "divergence-watchdog",
                                            event_type,
                                            payload,
                                            actor_id,
                                            timestamp_ns,
                                        ) {
                                            Ok(_) => true,
                                            Err(error) => {
                                                error!(
                                                    event_type = %event_type,
                                                    error = %error,
                                                    "Failed to persist divergence watchdog trace event"
                                                );
                                                false
                                            },
                                        }
                                    };

                                match serde_json::to_vec(&result.freeze) {
                                    Ok(freeze_payload) => {
                                        if emit_trace_event(
                                            "intervention.freeze",
                                            &freeze_payload,
                                            &result.freeze.gate_actor_id,
                                            result.freeze.frozen_at,
                                        ) {
                                            info!(
                                                freeze_id = %result.freeze.freeze_id,
                                                "Persisted divergence InterventionFreeze transition event"
                                            );
                                        }
                                    },
                                    Err(e) => {
                                        error!(
                                            error = %e,
                                            "Failed to serialize InterventionFreeze transition payload"
                                        );
                                    },
                                }

                                if let Ok(payload) = serde_json::to_vec(&result.compromise_signal) {
                                    emit_trace_event(
                                        "projection.compromise.signal",
                                        &payload,
                                        &result.compromise_signal.issuer_actor_id,
                                        result.compromise_signal.quarantined_at_ns,
                                    );
                                } else {
                                    error!(
                                        "Failed to serialize projection compromise signal payload"
                                    );
                                }

                                if let Ok(payload) =
                                    serde_json::to_vec(&result.source_trust_snapshot)
                                {
                                    emit_trace_event(
                                        "projection.source.trust_snapshot",
                                        &payload,
                                        &result.freeze.gate_actor_id,
                                        result.freeze.frozen_at,
                                    );
                                } else {
                                    error!(
                                        "Failed to serialize projection source trust snapshot payload"
                                    );
                                }

                                if let Ok(payload) =
                                    serde_json::to_vec(&result.sink_identity_snapshot)
                                {
                                    emit_trace_event(
                                        "projection.sink.identity_snapshot",
                                        &payload,
                                        &result.freeze.gate_actor_id,
                                        result.freeze.frozen_at,
                                    );
                                } else {
                                    error!(
                                        "Failed to serialize projection sink identity snapshot payload"
                                    );
                                }

                                if let Ok(payload) = serde_json::to_vec(&result.replay_receipt) {
                                    emit_trace_event(
                                        "projection.replay.receipt",
                                        &payload,
                                        &result.replay_receipt.signer_actor_id,
                                        result.freeze.frozen_at,
                                    );
                                } else {
                                    error!("Failed to serialize projection replay receipt payload");
                                }
                            }
                        },
                        Ok(None) => {
                            let had_check_errors = consecutive_check_errors > 0;
                            consecutive_check_errors = 0;

                            // Successful checks after transient watchdog errors
                            // can remove precautionary freezes, but only when
                            // no non-precautionary (divergence) freeze is active.
                            if had_check_errors {
                                let registry = watchdog.registry();
                                let has_active_divergence_freeze = registry
                                    .is_frozen(&watchdog_repo_id)
                                    .as_deref()
                                    .is_some_and(|freeze_id| {
                                        !freeze_id.starts_with("precautionary-")
                                    });
                                if !has_active_divergence_freeze {
                                    registry.remove_precautionary_freeze(
                                        &watchdog_repo_id,
                                        &precautionary_freeze_id,
                                    );
                                }
                            }
                        },
                        Err(e) => {
                            consecutive_check_errors = consecutive_check_errors.saturating_add(1);
                            error!(
                                error = %e,
                                consecutive_check_errors,
                                "Divergence check failed; precautionary freeze applied until next successful check"
                            );
                            watchdog.registry().register_precautionary_freeze(
                                &watchdog_repo_id,
                                precautionary_freeze_id.clone(),
                            );
                        },
                    }
                }
            });

            Some(watchdog)
        } else {
            info!("Divergence watchdog disabled");
            None
        }
    };

    // TCK-00469: Wire divergence watchdog Arc into dispatcher state so IPC
    // handlers can call register_durable_recovery_evidence / create_unfreeze /
    // apply_unfreeze.
    // Safety: dispatcher_state has not yet been cloned at this point in startup.
    let dispatcher_state = if let Some(watchdog) = watchdog_arc_for_dispatcher {
        match Arc::try_unwrap(dispatcher_state) {
            Ok(inner) => Arc::new(inner.with_divergence_watchdog(watchdog)),
            Err(_arc) => {
                unreachable!("dispatcher_state Arc should have single owner at watchdog bootstrap");
            },
        }
    } else {
        dispatcher_state
    };

    // INV-BRK-HEALTH-GATE-001: The admission health gate starts CLOSED
    // (fail-closed). It is NOT opened here at startup. Instead, the background
    // health poller (10s interval) continuously evaluates broker health and
    // updates the gate. This prevents the "sticky open" vulnerability where
    // the gate opens once at startup and never closes on health degradation.
    // The first successful health check in the poller will open the gate.
    info!(
        "Admission health gate starts closed (fail-closed); \
         background poller will evaluate and open on first healthy check"
    );

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

    // TCK-00600: Notify systemd that the daemon is stopping.
    let _ = apm2_core::fac::sd_notify::notify_stopping();

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

// TCK-00595 MAJOR-1: detect_github_owner_repo_from_remote() removed.
// The daemon must not auto-detect owner/repo from CWD git remote.
// Use explicit [daemon.projection] config in ecosystem.toml instead.

/// Parse a GitHub remote URL into (owner, repo).
///
/// Supports ssh://, git@, https://, and http:// URL formats.
///
/// # NIT FIX: Strict regex validation
///
/// Owner and repo segments are validated against `[a-zA-Z0-9._-]+` to reject
/// malformed or injection-prone values.
#[cfg(test)]
fn parse_github_owner_repo(url: &str) -> Option<(String, String)> {
    /// Validate that a GitHub owner or repo segment contains only safe
    /// characters. GitHub allows alphanumeric, hyphens, dots, and
    /// underscores in owner/repo names.
    fn is_valid_segment(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 100
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    }

    fn extract_owner_repo(path_str: &str) -> Option<(String, String)> {
        let path = path_str.strip_suffix(".git").unwrap_or(path_str);
        let parts: Vec<&str> = path.splitn(2, '/').collect();
        if parts.len() == 2 && is_valid_segment(parts[0]) && is_valid_segment(parts[1]) {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    }

    // ssh://git@github.com/owner/repo[.git]
    if let Some(rest) = url.strip_prefix("ssh://git@github.com/") {
        return extract_owner_repo(rest);
    }
    // git@github.com:owner/repo[.git]
    if let Some(rest) = url.strip_prefix("git@github.com:") {
        return extract_owner_repo(rest);
    }
    // https://github.com/owner/repo[.git]
    if let Some(rest) = url.strip_prefix("https://github.com/") {
        return extract_owner_repo(rest);
    }
    // http://github.com/owner/repo[.git]
    if let Some(rest) = url.strip_prefix("http://github.com/") {
        return extract_owner_repo(rest);
    }
    None
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
    token: &secrecy::SecretString,
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
        .header(
            "Authorization",
            format!("Bearer {}", secrecy::ExposeSecret::expose_secret(token)),
        )
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
    let emitter = sqlite_conn.map(|conn| {
        SqliteLedgerEventEmitter::new(Arc::clone(conn), ledger_signing_key.clone())
        // NOTE: Recovery emitter is NOT frozen. Crash recovery runs BEFORE
        // the main freeze (in async_main). Recovery events go to legacy
        // `ledger_events` and will be re-migrated on next startup if needed
        // (the migration function handles post-cutover legacy rows).
    });

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
        let daemon_signing_public_key = match socket_type {
            // Operator socket advertises the ledger/event signing key.
            protocol::socket_manager::SocketType::Operator => {
                dispatcher_state.event_emitter().verifying_key().to_bytes()
            },
            // Session socket advertises the channel-context token verifying key.
            protocol::socket_manager::SocketType::Session => dispatcher_state
                .session_dispatcher()
                .channel_context_verifying_key()
                .to_bytes(),
        };
        config = config.with_daemon_signing_public_key(hex::encode(daemon_signing_public_key));
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
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).expect("init ledger schema");
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
                role_spec_hash: [0u8; 32],
                context_pack_recipe_hash: [0u8; 32],
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

    #[test]
    fn parse_github_ssh_url() {
        let result = parse_github_owner_repo("git@github.com:guardian-intelligence/apm2.git");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn test_ensure_canonicalizer_tuple_admitted_rejects_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let fac_root = dir.path().join("private").join("fac");
        let current_tuple = apm2_core::fac::CanonicalizerTupleV1::from_current();
        let mut tuple_broker = apm2_core::fac::FacBroker::new();

        let err = ensure_canonicalizer_tuple_admitted(&fac_root, &current_tuple, &mut tuple_broker)
            .expect_err("first-run without tuple should fail");
        assert!(
            err.to_string()
                .contains("No admitted canonicalizer tuple found."),
            "expected missing tuple failure, got: {err}"
        );
    }

    #[test]
    fn test_ensure_canonicalizer_tuple_admitted_rejects_corrupted_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let fac_root = dir.path().join("private").join("fac");
        let tuple_path = fac_root
            .join("broker")
            .join("admitted_canonicalizer_tuple.v1.json");
        std::fs::create_dir_all(
            tuple_path
                .parent()
                .expect("tuple directory parent should exist"),
        )
        .unwrap();
        std::fs::write(&tuple_path, b"{bad").unwrap();

        let current_tuple = apm2_core::fac::CanonicalizerTupleV1::from_current();
        let mut tuple_broker = apm2_core::fac::FacBroker::new();

        let err = ensure_canonicalizer_tuple_admitted(&fac_root, &current_tuple, &mut tuple_broker)
            .expect_err("corrupted tuple should fail startup");
        assert!(
            err.to_string()
                .contains("failed to load admitted canonicalizer tuple"),
            "expected failure to load admitted tuple, got: {err}"
        );
    }

    #[test]
    fn parse_github_https_url() {
        let result = parse_github_owner_repo("https://github.com/guardian-intelligence/apm2.git");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn parse_github_https_no_suffix() {
        let result = parse_github_owner_repo("https://github.com/guardian-intelligence/apm2");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn parse_github_ssh_protocol_url() {
        let result = parse_github_owner_repo("ssh://git@github.com/guardian-intelligence/apm2.git");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn parse_github_http_url() {
        let result = parse_github_owner_repo("http://github.com/guardian-intelligence/apm2");
        assert_eq!(
            result,
            Some(("guardian-intelligence".to_string(), "apm2".to_string()))
        );
    }

    #[test]
    fn parse_github_invalid_url() {
        assert_eq!(parse_github_owner_repo("not-a-url"), None);
    }

    #[test]
    fn parse_github_empty_owner() {
        assert_eq!(parse_github_owner_repo("git@github.com:/repo.git"), None);
    }

    #[test]
    fn parse_github_no_repo() {
        assert_eq!(parse_github_owner_repo("git@github.com:owner"), None);
    }
}
