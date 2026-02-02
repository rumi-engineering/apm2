//! apm2-daemon - AI CLI Process Manager Daemon
//!
//! This is the main daemon binary that manages AI CLI processes.
//!
//! # Dual-Socket Topology (TCK-00249)
//!
//! The daemon uses a dual-socket architecture for privilege separation:
//! - **Operator socket** (`operator.sock`, mode 0600): Privileged operations
//! - **Session socket** (`session.sock`, mode 0660): Session-scoped operations
//!
//! See RFC-0017 for architecture details.

mod handlers;
mod ipc_server;
// mod protocol; // Use library crate instead to avoid dead code warnings
mod state;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use apm2_core::bootstrap::verify_bootstrap_hash;
use apm2_core::config::EcosystemConfig;
use apm2_core::process::ProcessState;
use apm2_core::schema_registry::{InMemorySchemaRegistry, register_kernel_schemas};
use apm2_core::supervisor::Supervisor;
use apm2_daemon::protocol; // Import from library
use apm2_daemon::protocol::socket_manager::{SocketManager, SocketManagerConfig};
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
}

/// Daemon configuration derived from args and config file.
struct DaemonConfig {
    config: EcosystemConfig,
    operator_socket_path: PathBuf,
    session_socket_path: PathBuf,
    pid_path: PathBuf,
    /// State file path for persistent session registry (TCK-00266).
    state_file_path: PathBuf,
}

impl DaemonConfig {
    fn new(args: &Args) -> Result<Self> {
        // Load configuration
        let config = if args.config.exists() {
            EcosystemConfig::from_file(&args.config).context("failed to load configuration")?
        } else {
            info!("No config file found, using defaults");
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    // Daemonize if requested
    #[allow(unsafe_code)] // fork() requires unsafe
    if !args.no_daemon {
        #[cfg(unix)]
        {
            use nix::unistd::{ForkResult, fork, setsid};

            info!("Daemonizing...");

            // First fork
            match unsafe { fork() }? {
                ForkResult::Parent { .. } => {
                    // Parent exits
                    std::process::exit(0);
                },
                ForkResult::Child => {},
            }

            // Create new session
            setsid()?;

            // Second fork
            match unsafe { fork() }? {
                ForkResult::Parent { .. } => {
                    // Parent exits
                    std::process::exit(0);
                },
                ForkResult::Child => {},
            }

            // Change to root directory
            std::env::set_current_dir("/")?;
        }

        #[cfg(not(unix))]
        {
            warn!("Daemonization not supported on this platform, running in foreground");
        }
    }

    // Load configuration and initialize
    let daemon_config = DaemonConfig::new(&args)?;
    let supervisor = init_supervisor(&daemon_config.config);

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

    // Start dual-socket IPC server (TCK-00249)
    // This replaces the legacy single-socket JSON IPC
    let socket_manager = Arc::new(socket_manager);
    let ipc_state = state.clone();
    let ipc_socket_manager = Arc::clone(&socket_manager);
    let ipc_task = tokio::spawn(async move {
        if let Err(e) = run_socket_manager_server(ipc_socket_manager, ipc_state).await {
            error!("IPC server error: {}", e);
        }
    });

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
        _ = ipc_task => {
            info!("IPC server exited");
        }
        _ = signal_task => {
            info!("Signal handler triggered shutdown");
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

/// Run the dual-socket IPC server using `SocketManager` (TCK-00249).
///
/// This replaces the legacy single-socket JSON IPC with the new
/// privilege-separated dual-socket topology defined in RFC-0017.
async fn run_socket_manager_server(
    socket_manager: Arc<SocketManager>,
    state: SharedState,
) -> Result<()> {
    info!("Dual-socket IPC server started");

    loop {
        // Check for shutdown
        if state.is_shutdown_requested() {
            info!("Dual-socket IPC server shutting down");
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
async fn handle_dual_socket_connection(
    mut connection: protocol::server::Connection,
    socket_type: protocol::socket_manager::SocketType,
    state: SharedState,
) -> Result<()> {
    use apm2_core::ipc::{IpcRequest, IpcResponse};
    use futures::{SinkExt, StreamExt};

    info!(
        socket_type = %socket_type,
        privileged = connection.is_privileged(),
        "New dual-socket connection"
    );

    // Upgrade to full frame size after connection is established
    connection.upgrade_to_full_frame_size()?;

    // Process messages
    while let Some(frame_result) = connection.framed().next().await {
        match frame_result {
            Ok(frame) => {
                if frame.is_empty() {
                    // Empty frame signals connection close
                    break;
                }

                // Parse the request
                let request: IpcRequest = match serde_json::from_slice(&frame) {
                    Ok(req) => req,
                    Err(e) => {
                        warn!("Failed to parse request: {e}");
                        continue;
                    },
                };

                // Check privilege level for privileged operations
                if requires_privilege(&request) && !connection.is_privileged() {
                    warn!(
                        "Unprivileged client attempted privileged operation: {:?}",
                        request
                    );
                    let response = IpcResponse::Error {
                        code: apm2_core::ipc::ErrorCode::InvalidRequest,
                        message: "operation requires privileged (operator) connection".to_string(),
                    };
                    let json: bytes::Bytes = serde_json::to_vec(&response)?.into();
                    connection.framed().send(json).await?;
                    continue;
                }

                // Dispatch to handler
                let response = handlers::dispatch(request, &state).await;

                // Send response
                let json: bytes::Bytes = serde_json::to_vec(&response)?.into();
                connection.framed().send(json).await?;
            },
            Err(e) => {
                warn!("Frame error: {e}");
                break;
            },
        }
    }

    info!(socket_type = %socket_type, "Connection closed");
    Ok(())
}

/// Check if a request requires privileged (operator) access.
///
/// TCK-00249: Uses default-deny model. Session socket connections are only
/// allowed to perform a small whitelist of safe operations. All other
/// operations require privileged (operator) connection.
///
/// # Security (Holonic Seclusion)
///
/// Session socket (mode 0660) is accessible to group users. To maintain
/// seclusion, we only allow `Ping` which cannot leak information about
/// processes, credentials, logs, or other sensitive data.
///
/// Operations that would violate seclusion if allowed on session socket:
/// - `TailLogs`: Would expose logs from ALL processes to any group user
/// - `ListProcesses`/`GetProcess`: Would expose process args (may contain
///   secrets)
/// - `ListCredentials`/`GetCredential`: Would expose credential metadata
/// - `Status`: Would expose daemon configuration details
/// - `*Episode*`: Episode state contains sensitive context
const fn requires_privilege(request: &apm2_core::ipc::IpcRequest) -> bool {
    use apm2_core::ipc::IpcRequest;
    // Default-deny: only explicitly whitelisted operations are unprivileged
    !matches!(
        request,
        // Session-safe operations (do not leak sensitive information)
        IpcRequest::Ping
    )
}
