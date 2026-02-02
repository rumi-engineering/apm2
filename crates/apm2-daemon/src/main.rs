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
mod state;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use apm2_core::bootstrap::verify_bootstrap_hash;
use apm2_core::config::EcosystemConfig;
use apm2_core::process::ProcessState;
use apm2_core::schema_registry::{InMemorySchemaRegistry, register_kernel_schemas};
use apm2_core::supervisor::Supervisor;
use apm2_daemon::metrics::{SharedMetricsRegistry, new_shared_registry};
use apm2_daemon::protocol; // Import from library
use apm2_daemon::protocol::socket_manager::{SocketManager, SocketManagerConfig};
use axum::Router;
use axum::routing::get;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::state::{DaemonStateHandle, SharedState};

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

        Ok(Self {
            config,
            operator_socket_path,
            session_socket_path,
            pid_path,
            state_file_path,
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

/// Graceful shutdown: stop all running processes.
async fn shutdown_all_processes(state: &SharedState) {
    info!("Stopping all running processes...");

    let timeout = Duration::from_secs(10);

    // Collect all running processes
    let processes_to_stop: Vec<(String, u32)> = {
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
    };

    if processes_to_stop.is_empty() {
        info!("No running processes to stop");
        return;
    }

    info!("Stopping {} process instance(s)", processes_to_stop.len());

    // Stop each process
    for (name, instance) in processes_to_stop {
        // Take the runner out
        let runner = {
            let mut inner = state.write().await;
            let spec_id = inner.supervisor.get_spec(&name).map(|s| s.id);
            spec_id.and_then(|id| inner.remove_runner(id, instance))
        };

        if let Some(mut runner) = runner {
            if runner.state().is_running() {
                info!("Stopping {}-{}", name, instance);
                if let Err(e) = runner.stop(timeout).await {
                    warn!("Error stopping {}-{}: {}", name, instance, e);
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

    info!("All processes stopped");
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

    // TCK-00267: Crash recovery on startup
    // Before accepting new connections, recover any sessions from persistent state
    // and send LEASE_REVOKED signals to invalidate their leases.
    if let Err(e) = perform_crash_recovery(&state).await {
        warn!("Crash recovery failed: {e}");
        // Continue startup even if recovery fails - the daemon should still be
        // usable
    }

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

    // TCK-00279: Start ProtocolServer-only control plane
    // This is the ONLY control-plane listener. Legacy JSON IPC has been removed per
    // DD-009.
    let socket_manager = Arc::new(socket_manager);
    let ipc_state = state.clone();
    let ipc_socket_manager = Arc::clone(&socket_manager);
    let protocol_server_task = tokio::spawn(async move {
        if let Err(e) = run_socket_manager_server(ipc_socket_manager, ipc_state).await {
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
    }

    // Graceful shutdown
    info!("Shutting down daemon...");
    shutdown_all_processes(&state).await;

    // Cleanup sockets (SocketManager handles this in Drop, but explicit cleanup is
    // safer)
    if let Err(e) = socket_manager.cleanup() {
        warn!("Failed to cleanup sockets: {e}");
    }
    remove_pid_file(&daemon_config.pid_path);

    info!("Daemon shutdown complete");
    Ok(())
}

/// Perform crash recovery on daemon startup (TCK-00267).
///
/// This function:
/// 1. Loads any persistent session state from the previous daemon instance
/// 2. Sends `LEASE_REVOKED` signals to all recovered sessions
/// 3. Cleans up orphaned processes
/// 4. Ensures recovery completes within 5 seconds
///
/// # Arguments
///
/// * `state` - The daemon shared state (currently unused, but will be used for
///   session registry access when persistence is implemented)
///
/// # Returns
///
/// `Ok(())` if recovery succeeded or was not needed,
/// `Err(_)` if recovery failed (daemon should still start).
#[allow(
    clippy::unused_async,           // Will be async when session persistence is implemented
    clippy::cast_possible_truncation // Recovery timeout is always < 5s, well within u32
)]
async fn perform_crash_recovery(_state: &SharedState) -> Result<()> {
    use std::time::Instant;

    use apm2_daemon::episode::registry::{DEFAULT_RECOVERY_TIMEOUT_MS, RecoveryManager};

    let start = Instant::now();
    info!(
        timeout_ms = DEFAULT_RECOVERY_TIMEOUT_MS,
        "Starting crash recovery"
    );

    // Create the recovery manager with default timeout (5 seconds)
    let recovery_manager = RecoveryManager::new();

    // TODO: When session persistence is implemented, this will:
    // 1. Load persistent session state from disk/database
    // 2. Populate a session registry with recovered sessions
    // 3. Call recovery_manager.recover_sessions() with the registry
    //
    // For now, with in-memory only sessions, there's nothing to recover
    // after a daemon restart - all sessions are lost when the daemon exits.
    //
    // The recovery manager infrastructure is in place for future use when
    // persistent session state is implemented.

    // If there were sessions to recover, we would do:
    // let result = recovery_manager.recover_sessions(&session_registry, |signal| {
    //     // Send the LEASE_REVOKED signal to the session
    //     // This would typically be done via IPC or a notification mechanism
    //     Ok(())
    // })?;
    //
    // info!(
    //     sessions_recovered = result.sessions_recovered,
    //     lease_revoked_signals_sent = result.lease_revoked_signals_sent,
    //     orphaned_processes_cleaned = result.orphaned_processes_cleaned,
    //     recovery_time_ms = result.recovery_time_ms,
    //     "Crash recovery completed"
    // );

    let elapsed_ms = start.elapsed().as_millis() as u32;

    // Verify we completed within the timeout
    let timeout_ms = recovery_manager.timeout().as_millis() as u32;
    if elapsed_ms > timeout_ms {
        warn!(
            elapsed_ms = elapsed_ms,
            timeout_ms = timeout_ms,
            "Crash recovery exceeded timeout"
        );
        anyhow::bail!("crash recovery timeout exceeded");
    }

    info!(
        elapsed_ms = elapsed_ms,
        sessions_recovered = 0,
        "Crash recovery completed (no persistent sessions to recover)"
    );

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
/// # Acceptance Criteria (TCK-00279)
///
/// - No `ipc_server::run` invocation in default build
/// - Startup logs show only operator.sock + session.sock listeners
/// - Legacy socket path is absent
async fn run_socket_manager_server(
    socket_manager: Arc<SocketManager>,
    state: SharedState,
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
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_dual_socket_connection(connection, socket_type, conn_state).await
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
/// # JSON Downgrade Rejection (DD-009)
///
/// Per TCK-00287 and DD-009, JSON frames are rejected before reaching handlers.
/// The tag-based routing validates that the first byte is a valid message type
/// tag (1-4 for privileged, 1-4 for session). JSON frames starting with `{`
/// (0x7B = 123) are rejected as unknown message types.
async fn handle_dual_socket_connection(
    mut connection: protocol::server::Connection,
    socket_type: protocol::socket_manager::SocketType,
    _state: SharedState,
) -> Result<()> {
    use bytes::Bytes;
    use futures::StreamExt;
    use protocol::connection_handler::{HandshakeResult, perform_handshake};
    use protocol::dispatch::{ConnectionContext, PrivilegedDispatcher};
    use protocol::session_dispatch::SessionDispatcher;
    use protocol::session_token::TokenMinter;

    info!(
        socket_type = %socket_type,
        privileged = connection.is_privileged(),
        "New ProtocolServer connection"
    );

    // Perform mandatory handshake
    match perform_handshake(&mut connection).await? {
        HandshakeResult::Success => {
            info!(socket_type = %socket_type, "Handshake completed successfully");
        },
        HandshakeResult::Failed => {
            warn!(socket_type = %socket_type, "Handshake failed, closing connection");
            return Ok(());
        },
        HandshakeResult::ConnectionClosed => {
            info!(socket_type = %socket_type, "Connection closed during handshake");
            return Ok(());
        },
    }

    // TCK-00287: Wire up tag-based ProtocolServer dispatchers
    // Create connection context based on socket type
    let ctx = match socket_type {
        protocol::socket_manager::SocketType::Operator => {
            ConnectionContext::privileged(connection.peer_credentials().cloned())
        },
        protocol::socket_manager::SocketType::Session => {
            ConnectionContext::session(connection.peer_credentials().cloned(), None)
        },
    };

    // Create dispatchers
    // Note: Using stub implementations for now. Production would use shared
    // instances with proper registries, metrics, etc.
    let privileged_dispatcher = PrivilegedDispatcher::new();
    let session_dispatcher =
        SessionDispatcher::new(TokenMinter::new(TokenMinter::generate_secret()));

    // TCK-00287: Message dispatch loop
    // Process incoming frames until connection closes or error
    info!(socket_type = %socket_type, "Entering message dispatch loop");

    while let Some(frame_result) = connection.framed().next().await {
        let frame = match frame_result {
            Ok(frame) => frame,
            Err(e) => {
                warn!(socket_type = %socket_type, error = %e, "Frame read error");
                break;
            },
        };

        // TCK-00287: JSON downgrade rejection (DD-009 fail-closed)
        // Validate frame before dispatch. JSON frames start with '{' (0x7B = 123)
        // or '[' (0x5B = 91) which are not valid message type tags.
        // The dispatcher's tag validation will reject these, but we add an
        // explicit check here for clearer error messaging.
        if !frame.is_empty() && is_json_frame(&frame) {
            warn!(
                socket_type = %socket_type,
                first_byte = frame[0],
                "JSON downgrade attempt rejected - protocol requires tag-based binary frames"
            );
            // Per DD-009: fail-closed, no JSON processing allowed
            continue;
        }

        // Route to appropriate dispatcher based on socket type
        // Each dispatcher returns its own response type, so we handle them separately
        let frame_bytes = Bytes::from(frame.to_vec());
        match socket_type {
            protocol::socket_manager::SocketType::Operator => {
                match privileged_dispatcher.dispatch(&frame_bytes, &ctx) {
                    Ok(response) => {
                        info!(socket_type = %socket_type, "Privileged request dispatched successfully");
                        // TODO: Send response back to client when bidirectional IPC is needed
                        drop(response);
                    },
                    Err(e) => {
                        warn!(socket_type = %socket_type, error = %e, "Privileged dispatch error");
                    },
                }
            },
            protocol::socket_manager::SocketType::Session => {
                match session_dispatcher.dispatch(&frame_bytes, &ctx) {
                    Ok(response) => {
                        info!(socket_type = %socket_type, "Session request dispatched successfully");
                        // TODO: Send response back to client when bidirectional IPC is needed
                        drop(response);
                    },
                    Err(e) => {
                        warn!(socket_type = %socket_type, error = %e, "Session dispatch error");
                    },
                }
            },
        }
    }

    info!(socket_type = %socket_type, "Connection closed");
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
