//! apm2 - AI CLI Process Manager
//!
//! CLI client for managing AI CLI processes like Claude Code, Gemini CLI, etc.

use std::path::PathBuf;

use anyhow::{Context, Result};
use apm2_core::bootstrap::verify_bootstrap_hash;
use apm2_core::schema_registry::{InMemorySchemaRegistry, register_kernel_schemas};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod client;
mod commands;
mod exit_codes;

/// apm2 - AI CLI Process Manager
#[derive(Parser, Debug)]
#[command(name = "apm2")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to ecosystem configuration file
    #[arg(short, long, default_value = "ecosystem.toml")]
    config: PathBuf,

    /// Path to Unix socket
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "warn")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    // === Daemon management ===
    /// Start the daemon (background by default)
    Daemon {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        no_daemon: bool,
    },

    /// Stop the daemon (graceful shutdown)
    Kill,

    // === Process management ===
    /// Start a configured process (all instances)
    Start {
        /// Process name
        name: String,
    },

    /// Stop a configured process (all instances)
    Stop {
        /// Process name
        name: String,
    },

    /// Restart a configured process (stop then start)
    Restart {
        /// Process name
        name: String,
    },

    /// Graceful reload (rolling restart) [daemon support pending]
    Reload {
        /// Process name
        name: String,
    },

    // === Process info ===
    /// List configured processes
    #[command(alias = "ls")]
    List,

    /// Show process details
    Status {
        /// Process name
        name: String,
    },

    /// Tail process logs [daemon support pending]
    Logs {
        /// Process name
        name: String,

        /// Number of lines to show
        #[arg(short = 'n', long, default_value = "20")]
        lines: u32,

        /// Follow mode (stream new lines)
        #[arg(short, long)]
        follow: bool,
    },

    // === Credential management ===
    /// Credential management [daemon support pending]
    #[command(subcommand)]
    Creds(CredsCommands),

    // === CAC (Context-as-Code) operations ===
    /// Context-as-Code (CAC) commands
    Cac(commands::cac::CacCommand),

    // === Pack (ContextPack) operations ===
    /// Pack commands (compile and manage `ContextPacks`)
    Pack(commands::pack::PackCommand),

    // === Export (CAC export pipeline) ===
    /// Export a compiled context pack to target profile layout
    Export(commands::export::ExportArgs),

    // === Coordination (Work queue processing) ===
    /// Coordinate work queue processing with budget enforcement
    Coordinate(commands::coordinate::CoordinateArgs),

    // === Episode management (RFC-0013) ===
    /// Episode commands for bounded execution management
    Episode(commands::episode::EpisodeCommand),

    // === Consensus cluster management (RFC-0014) ===
    /// Consensus commands for cluster status and diagnostics
    Consensus(commands::consensus::ConsensusCommand),

    // === Work queue operations (TCK-00288) ===
    /// Work queue commands (claim work from queue)
    Work(commands::work::WorkCommand),

    // === Tool operations (TCK-00288) ===
    /// Tool commands (request tool execution via session socket)
    Tool(commands::tool::ToolCommand),

    // === Event operations (TCK-00288) ===
    /// Event commands (emit events to ledger via session socket)
    Event(commands::event::EventCommand),

    // === Capability operations (TCK-00288) ===
    /// Capability commands (issue capabilities to sessions via operator socket)
    Capability(commands::capability::CapabilityCommand),

    // === Evidence operations (TCK-00288) ===
    /// Evidence commands (publish evidence artifacts via session socket)
    Evidence(commands::evidence::EvidenceCommand),

    // === FAC (Forge Admission Cycle) productivity (TCK-00333) ===
    /// FAC commands (ledger/CAS oriented debug UX)
    Fac(commands::fac::FacCommand),

    // === Factory (Agent) orchestration ===
    /// Factory commands (runs Markdown specs)
    #[command(subcommand)]
    Factory(FactoryCommands),
}

#[derive(Subcommand, Debug)]
enum CredsCommands {
    /// List credential profiles [daemon support pending]
    List,

    /// Add a new credential profile [daemon support pending]
    Add {
        /// Profile ID
        profile_id: String,

        /// Provider (claude, gemini, openai)
        #[arg(short, long)]
        provider: String,

        /// Auth method (`api_key`, `session_token`, oauth)
        #[arg(short, long, default_value = "api_key")]
        auth_method: String,
    },

    /// Remove a credential profile [daemon support pending]
    Remove {
        /// Profile ID
        profile_id: String,
    },

    /// Force refresh a credential profile [daemon support pending]
    Refresh {
        /// Profile ID
        profile_id: String,
    },

    /// Switch credentials for a running process [daemon support pending]
    Switch {
        /// Process name
        process: String,

        /// New profile ID
        profile: String,
    },

    /// Print provider login instructions (does not store credentials)
    Login {
        /// Provider (claude, gemini, openai)
        provider: String,

        /// Profile ID to reference in printed instructions
        #[arg(short, long)]
        profile_id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum FactoryCommands {
    /// Run a Markdown spec with an agent CLI (currently Claude Code)
    Run {
        /// Path to the spec file (PRD, RFC, or Ticket)
        spec_file: PathBuf,

        /// Output format (`text` or `json`)
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
    },

    /// CCP (Code Context Protocol) commands
    Ccp(commands::factory::ccp::CcpCommand),

    /// Impact Map commands (PRD requirement to CCP component mapping)
    ImpactMap(commands::factory::impact_map::ImpactMapCommand),

    /// RFC commands (RFC framing from Impact Map and CCP)
    Rfc(commands::factory::rfc::RfcCommand),

    /// Ticket commands (emit tickets from RFC decomposition)
    Tickets(commands::factory::tickets::TicketsCommand),

    /// Compile pipeline (end-to-end PRD to tickets)
    Compile(commands::factory::compile::CompileArgs),

    /// Refactor radar (maintenance recommendations)
    Refactor(commands::factory::refactor::RefactorCommand),
}

fn main() -> Result<()> {
    // Verify bootstrap schema integrity before proceeding.
    // This is a critical security check that must pass before any CAC operations.
    verify_bootstrap_hash().context("bootstrap schema integrity check failed")?;

    // Validate kernel schema registration capability on startup (TCK-00181).
    // The CLI is short-lived, so we verify that kernel schemas CAN be registered
    // correctly. The actual long-lived registry is maintained by the daemon.
    // This ensures the CLI can validate schema-related operations before
    // forwarding to the daemon.
    let registry = InMemorySchemaRegistry::new();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .context("Failed to build tokio runtime for kernel schema registration")?
        .block_on(register_kernel_schemas(&registry))
        .context("kernel schema registration failed")?;
    // Registry is intentionally dropped here - CLI operations use daemon's registry
    drop(registry);

    let cli = Cli::parse();

    // Initialize logging
    let filter = EnvFilter::try_new(&cli.log_level).unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    // TCK-00288: Deprecation warning for --socket flag
    // The --socket flag is deprecated and maps to operator_socket only.
    // Users should migrate to using config-based socket paths.
    if cli.socket.is_some() {
        eprintln!(
            "WARNING: --socket is deprecated and will be removed in a future version.\n\
             The flag maps to operator_socket only. For dual-socket routing (operator/session),\n\
             configure socket paths in ecosystem.toml instead."
        );
    }

    // Determine socket paths (TCK-00288: dual-socket privilege separation)
    // - operator_socket: For privileged operations (ClaimWork, SpawnEpisode,
    //   Shutdown)
    // - session_socket: For session-scoped operations (RequestTool, EmitEvent)
    let (operator_socket, session_socket) = if let Some(ref socket) = cli.socket {
        // Legacy --socket flag maps to operator_socket only
        (socket.clone(), socket.clone())
    } else if cli.config.exists() {
        if let Ok(config) = apm2_core::config::EcosystemConfig::from_file(&cli.config) {
            (config.daemon.operator_socket, config.daemon.session_socket)
        } else {
            (default_operator_socket(), default_session_socket())
        }
    } else {
        (default_operator_socket(), default_session_socket())
    };

    // Alias for backward compatibility
    let socket_path = operator_socket.clone();

    match cli.command {
        Commands::Daemon { no_daemon } => commands::daemon::run(&cli.config, no_daemon),
        Commands::Kill => commands::daemon::kill(&socket_path),
        Commands::Start { name } => commands::process::start(&socket_path, &name),
        Commands::Stop { name } => commands::process::stop(&socket_path, &name),
        Commands::Restart { name } => commands::process::restart(&socket_path, &name),
        Commands::Reload { name } => commands::process::reload(&socket_path, &name),
        Commands::List => commands::process::list(&socket_path),
        Commands::Status { name } => commands::process::status(&socket_path, &name),
        Commands::Logs {
            name,
            lines,
            follow,
        } => commands::process::logs(&socket_path, &name, lines, follow),
        Commands::Creds(creds_cmd) => match creds_cmd {
            CredsCommands::List => commands::creds::list(&socket_path),
            CredsCommands::Add {
                profile_id,
                provider,
                auth_method,
            } => commands::creds::add(&socket_path, &profile_id, &provider, &auth_method),
            CredsCommands::Remove { profile_id } => {
                commands::creds::remove(&socket_path, &profile_id)
            },
            CredsCommands::Refresh { profile_id } => {
                commands::creds::refresh(&socket_path, &profile_id)
            },
            CredsCommands::Switch { process, profile } => {
                commands::creds::switch(&socket_path, &process, &profile)
            },
            CredsCommands::Login {
                provider,
                profile_id,
            } => commands::creds::login(&socket_path, &provider, profile_id.as_deref()),
        },
        Commands::Cac(cac_cmd) => {
            // CAC commands use specific exit codes per TCK-00133:
            // 0=success, 1=validation_error, 2=replay_violation
            // We use std::process::exit to bypass anyhow Result handling
            // and ensure precise exit codes are returned.
            let exit_code = commands::cac::run_cac(&cac_cmd);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Pack(pack_cmd) => {
            // Pack commands use specific exit codes per TCK-00139:
            // 0=success, 1=budget_exceeded, 2=validation_error
            // We use std::process::exit to bypass anyhow Result handling
            // and ensure precise exit codes are returned.
            let exit_code = commands::pack::run_pack(&pack_cmd);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Export(export_args) => {
            // Export commands use specific exit codes per TCK-00143:
            // 0=success, 1=error, 2=conformance_failure
            // We use std::process::exit to bypass anyhow Result handling
            // and ensure precise exit codes are returned.
            let exit_code = commands::export::run_export(&export_args);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Coordinate(coordinate_args) => {
            // Coordinate commands use specific exit codes per TCK-00153:
            // 0=success (WORK_COMPLETED), 1=aborted, 2=invalid_args
            // TCK-00346: Uses operator_socket for privileged ClaimWork/SpawnEpisode
            // operations, and session_socket for session observation/polling.
            // We use std::process::exit to bypass anyhow Result handling and
            // ensure precise exit codes are returned.
            let exit_code = commands::coordinate::run_coordinate(
                &coordinate_args,
                &operator_socket,
                &session_socket,
            );
            std::process::exit(i32::from(exit_code));
        },
        Commands::Episode(episode_cmd) => {
            // Episode commands use RFC-0018 exit codes.
            // We use std::process::exit to bypass anyhow Result handling
            // and ensure precise exit codes are returned.
            let exit_code =
                commands::episode::run_episode(&episode_cmd, &operator_socket, &session_socket);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Consensus(consensus_cmd) => {
            // Consensus commands use specific exit codes per TCK-00193:
            // 0=success, 1=error, 2=cluster_unhealthy
            // We use std::process::exit to bypass anyhow Result handling
            // and ensure precise exit codes are returned.
            let exit_code = commands::consensus::run_consensus(&consensus_cmd, &socket_path);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Work(work_cmd) => {
            // Work commands use operator_socket for privileged ClaimWork operation.
            // Exit codes: 0=success, 1=error
            let exit_code = commands::work::run_work(&work_cmd, &operator_socket);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Tool(tool_cmd) => {
            // Tool commands use session_socket for session-scoped RequestTool operation.
            // Exit codes: 0=success, 1=error
            let exit_code = commands::tool::run_tool(&tool_cmd, &session_socket);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Event(event_cmd) => {
            // Event commands use session_socket for session-scoped EmitEvent operation.
            // Exit codes: 0=success, 1=error
            let exit_code = commands::event::run_event(&event_cmd, &session_socket);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Capability(capability_cmd) => {
            // Capability commands use operator_socket for privileged IssueCapability
            // operation. Exit codes per RFC-0018.
            let exit_code = commands::capability::run_capability(&capability_cmd, &operator_socket);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Evidence(evidence_cmd) => {
            // Evidence commands use session_socket for session-scoped PublishEvidence
            // operation. Exit codes per RFC-0018.
            let exit_code = commands::evidence::run_evidence(&evidence_cmd, &session_socket);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Fac(fac_cmd) => {
            // FAC commands operate directly on ledger/CAS files (no daemon required).
            // Exit codes per RFC-0018.
            let exit_code = commands::fac::run_fac(&fac_cmd);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Factory(cmd) => match cmd {
            FactoryCommands::Run { spec_file, format } => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("Failed to build tokio runtime")?;
                rt.block_on(commands::factory::run(&spec_file, &format))
            },
            FactoryCommands::Ccp(ccp_cmd) => commands::factory::ccp::run_ccp(&ccp_cmd),
            FactoryCommands::ImpactMap(impact_map_cmd) => {
                commands::factory::impact_map::run_impact_map(&impact_map_cmd)
            },
            FactoryCommands::Rfc(rfc_cmd) => commands::factory::rfc::run_rfc(&rfc_cmd),
            FactoryCommands::Tickets(tickets_cmd) => {
                commands::factory::tickets::run_tickets(&tickets_cmd)
            },
            FactoryCommands::Compile(compile_args) => {
                commands::factory::compile::run_compile(&compile_args)
            },
            FactoryCommands::Refactor(refactor_cmd) => {
                commands::factory::refactor::run_refactor(&refactor_cmd)
            },
        },
    }
}

/// Returns the default operator socket path.
///
/// Uses `XDG_RUNTIME_DIR` if available, otherwise /tmp/apm2.
fn default_operator_socket() -> PathBuf {
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| PathBuf::from("/tmp/apm2/operator.sock"),
        |runtime_dir| {
            PathBuf::from(runtime_dir)
                .join("apm2")
                .join("operator.sock")
        },
    )
}

/// Returns the default session socket path.
///
/// Uses `XDG_RUNTIME_DIR` if available, otherwise /tmp/apm2.
fn default_session_socket() -> PathBuf {
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| PathBuf::from("/tmp/apm2/session.sock"),
        |runtime_dir| PathBuf::from(runtime_dir).join("apm2").join("session.sock"),
    )
}
