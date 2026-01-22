//! apm2 - AI CLI Process Manager
//!
//! CLI client for managing AI CLI processes like Claude Code, Gemini CLI, etc.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod commands;

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
    /// Start the daemon
    Daemon {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        no_daemon: bool,
    },

    /// Kill the daemon
    Kill,

    // === Process management ===
    /// Start process(es)
    Start {
        /// Process name (or 'all')
        name: String,
    },

    /// Stop process(es)
    Stop {
        /// Process name (or 'all')
        name: String,
    },

    /// Restart process(es)
    Restart {
        /// Process name (or 'all')
        name: String,
    },

    /// Graceful reload (rolling restart)
    Reload {
        /// Process name (or 'all')
        name: String,
    },

    // === Process info ===
    /// List all processes
    #[command(alias = "ls")]
    List,

    /// Show process details
    Status {
        /// Process name
        name: String,
    },

    /// Tail process logs
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
    /// Credential management
    #[command(subcommand)]
    Creds(CredsCommands),
}

#[derive(Subcommand, Debug)]
enum CredsCommands {
    /// List credential profiles
    List,

    /// Add a new credential profile
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

    /// Remove a credential profile
    Remove {
        /// Profile ID
        profile_id: String,
    },

    /// Force refresh a credential profile
    Refresh {
        /// Profile ID
        profile_id: String,
    },

    /// Switch credentials for a running process
    Switch {
        /// Process name
        process: String,

        /// New profile ID
        profile: String,
    },

    /// Interactive login flow
    Login {
        /// Provider (claude, gemini, openai)
        provider: String,

        /// Profile ID to create
        #[arg(short, long)]
        profile_id: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = EnvFilter::try_new(&cli.log_level).unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    // Determine socket path
    let socket_path = cli.socket.clone().unwrap_or_else(|| {
        // Try to load from config, or use default
        if cli.config.exists() {
            if let Ok(config) = apm2_core::config::EcosystemConfig::from_file(&cli.config) {
                return config.daemon.socket;
            }
        }
        PathBuf::from("/var/run/apm2/apm2.sock")
    });

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
            } => commands::creds::login(&provider, profile_id.as_deref()),
        },
    }
}
