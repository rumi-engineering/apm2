//! apm2-daemon - AI CLI Process Manager Daemon
//!
//! This is the main daemon binary that manages AI CLI processes.

mod handlers;
mod ipc_server;
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

    /// Path to Unix socket
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Path to state file (reserved; not wired up yet)
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
    socket_path: PathBuf,
    pid_path: PathBuf,
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
        let socket_path = args
            .socket
            .clone()
            .unwrap_or_else(|| config.daemon.socket.clone());
        let pid_path = args
            .pid_file
            .clone()
            .unwrap_or_else(|| config.daemon.pid_file.clone());

        Ok(Self {
            config,
            socket_path,
            pid_path,
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

    // Create shared state with schema registry
    // The registry persists for the daemon's lifetime (TCK-00181)
    let state: SharedState = Arc::new(DaemonStateHandle::new(
        daemon_config.config.clone(),
        supervisor,
        registry, // Pass the registry created during bootstrap
    ));

    // Write PID file
    write_pid_file(&daemon_config.pid_path)?;

    info!(
        "apm2 daemon started (pid: {}, socket: {:?})",
        std::process::id(),
        daemon_config.socket_path
    );

    {
        let inner = state.read().await;
        info!("Managing {} processes", inner.supervisor.process_count());
    }

    // Start IPC server
    let socket_path = daemon_config.socket_path.clone();
    let ipc_state = state.clone();
    let ipc_task = tokio::spawn(async move {
        if let Err(e) = ipc_server::run(&socket_path, ipc_state).await {
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

    // Cleanup
    if daemon_config.socket_path.exists() {
        let _ = std::fs::remove_file(&daemon_config.socket_path);
    }
    remove_pid_file(&daemon_config.pid_path);

    info!("Daemon shutdown complete");
    Ok(())
}
