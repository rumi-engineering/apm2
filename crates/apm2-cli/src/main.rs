#![allow(clippy::doc_markdown)]
#![allow(clippy::too_long_first_doc_paragraph)]
#![allow(clippy::doc_lazy_continuation)]
//! apm2 - AI CLI Process Manager
//!
//! CLI client for managing AI CLI processes like Claude Code, Gemini CLI, etc.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use apm2_core::bootstrap::verify_bootstrap_hash;
use apm2_core::config::{
    normalize_operator_socket_path_with_runtime, normalize_session_socket_path_with_runtime,
};
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

        /// Daemon subcommands.
        #[command(subcommand)]
        command: Option<DaemonSubcommand>,
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

    // === Work queue operations (RFC-0032::REQ-0090) ===
    /// Work queue commands (claim work from queue)
    Work(commands::work::WorkCommand),

    // === Tool operations (RFC-0032::REQ-0090) ===
    /// Tool commands (request tool execution via session socket)
    Tool(commands::tool::ToolCommand),

    // === Event operations (RFC-0032::REQ-0090) ===
    /// Event commands (emit events to ledger via session socket)
    Event(commands::event::EventCommand),

    // === Capability operations (RFC-0032::REQ-0090) ===
    /// Capability commands (issue capabilities to sessions via operator socket)
    Capability(commands::capability::CapabilityCommand),

    // === Evidence operations (RFC-0032::REQ-0090) ===
    /// Evidence commands (publish evidence artifacts via session socket)
    Evidence(commands::evidence::EvidenceCommand),

    // === FAC (Forge Admission Cycle) operational surface ===
    /// FAC operations and diagnostics (JSON-first)
    Fac(commands::fac::FacCommand),

    // === Factory (Agent) orchestration ===
    /// Factory commands (runs Markdown specs)
    #[command(subcommand)]
    Factory(FactoryCommands),
}

#[derive(Subcommand, Debug)]
/// Daemon-level management subcommands.
pub enum DaemonSubcommand {
    /// Install and enable the apm2-daemon systemd user service.
    Install {
        /// Enable linger for user services after logout
        #[arg(long)]
        enable_linger: bool,
    },

    /// Run daemon health checks and prerequisite validation.
    Doctor {
        /// Output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
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

    /// Compile pipeline (end-to-end PRD to tickets)
    Compile(commands::factory::compile::CompileArgs),
}

fn main() -> Result<()> {
    // Verify bootstrap schema integrity before proceeding.
    // This is a critical security check that must pass before any CAC operations.
    verify_bootstrap_hash().context("bootstrap schema integrity check failed")?;

    // Validate kernel schema registration capability on startup
    // (RFC-0033::REQ-0045). The CLI is short-lived, so we verify that kernel
    // schemas CAN be registered correctly. The actual long-lived registry is
    // maintained by the daemon. This ensures the CLI can validate
    // schema-related operations before forwarding to the daemon.
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

    // RFC-0032::REQ-0090: Deprecation warning for --socket flag
    // The --socket flag is deprecated and maps to operator_socket only.
    // Users should migrate to using config-based socket paths.
    if cli.socket.is_some() {
        eprintln!(
            "WARNING: --socket is deprecated and will be removed in a future version.\n\
             The flag maps to operator_socket only. For dual-socket routing (operator/session),\n\
             configure socket paths in ecosystem.toml instead."
        );
    }

    // Resolve daemon config path from the git common-dir checkout root so all
    // worktrees target the same daemon by default.
    let daemon_config_path = resolve_daemon_config_path(&cli.config);

    // Determine socket paths (RFC-0032::REQ-0090: dual-socket privilege separation)
    // - operator_socket: For privileged operations (ClaimWork, SpawnEpisode,
    //   Shutdown)
    // - session_socket: For session-scoped operations (RequestTool, EmitEvent)
    let (operator_socket, session_socket) =
        resolve_cli_socket_paths(cli.socket.as_ref(), &daemon_config_path);

    // Alias for backward compatibility
    let socket_path = operator_socket.clone();

    match cli.command {
        Commands::Daemon { no_daemon, command } => match command {
            Some(DaemonSubcommand::Install { enable_linger }) => {
                commands::daemon::install(enable_linger)
            },
            Some(DaemonSubcommand::Doctor { json }) => {
                commands::daemon::doctor(&socket_path, &daemon_config_path, json)
            },
            None => commands::daemon::run(&daemon_config_path, no_daemon),
        },
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
            // CAC commands use specific exit codes per RFC-0011::REQ-0002:
            // 0=success, 1=validation_error, 2=replay_violation
            // We use std::process::exit to bypass anyhow Result handling
            // and ensure precise exit codes are returned.
            let exit_code = commands::cac::run_cac(&cac_cmd);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Pack(pack_cmd) => {
            // Pack commands use specific exit codes per RFC-0011::REQ-0003:
            // 0=success, 1=budget_exceeded, 2=validation_error
            // We use std::process::exit to bypass anyhow Result handling
            // and ensure precise exit codes are returned.
            let exit_code = commands::pack::run_pack(&pack_cmd);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Export(export_args) => {
            // Export commands use specific exit codes per RFC-0011::REQ-0005:
            // 0=success, 1=error, 2=conformance_failure
            // We use std::process::exit to bypass anyhow Result handling
            // and ensure precise exit codes are returned.
            let exit_code = commands::export::run_export(&export_args);
            std::process::exit(i32::from(exit_code));
        },
        Commands::Coordinate(coordinate_args) => {
            // Coordinate commands use specific exit codes per RFC-0032::REQ-0053:
            // 0=success (WORK_COMPLETED), 1=aborted, 2=invalid_args
            // RFC-0032::REQ-0136: Uses operator_socket for privileged
            // ClaimWork/SpawnEpisode operations, and session_socket for session
            // observation/polling. We use std::process::exit to bypass anyhow
            // Result handling and ensure precise exit codes are returned.
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
            // Consensus commands use specific exit codes per RFC-0033::REQ-0053:
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
            // FAC commands are primarily ledger/CAS-driven; work lifecycle
            // status/list subcommands route through operator IPC.
            // Exit codes per RFC-0018.
            // RFC-0032::REQ-0244 MAJOR-2 FIX: Thread config path so ensure_daemon_running
            // can forward --config when spawning the daemon.
            let exit_code = commands::fac::run_fac(
                &fac_cmd,
                &operator_socket,
                &session_socket,
                &daemon_config_path,
            );
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
            FactoryCommands::Compile(compile_args) => {
                commands::factory::compile::run_compile(&compile_args)
            },
        },
    }
}

/// Returns the default operator socket path.
///
/// Uses `XDG_RUNTIME_DIR` if available, otherwise `APM2_DATA_DIR` / XDG data.
fn default_operator_socket(runtime_dir: Option<&Path>) -> PathBuf {
    runtime_dir.map_or_else(
        || apm2_core::config::default_data_dir().join("operator.sock"),
        |runtime| runtime.join("apm2").join("operator.sock"),
    )
}

/// Returns the default session socket path.
///
/// Uses `XDG_RUNTIME_DIR` if available, otherwise `APM2_DATA_DIR` / XDG data.
fn default_session_socket(runtime_dir: Option<&Path>) -> PathBuf {
    runtime_dir.map_or_else(
        || apm2_core::config::default_data_dir().join("session.sock"),
        |runtime| runtime.join("apm2").join("session.sock"),
    )
}

fn resolve_cli_socket_paths(
    legacy_socket: Option<&PathBuf>,
    daemon_config_path: &Path,
) -> (PathBuf, PathBuf) {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    resolve_cli_socket_paths_with_runtime(legacy_socket, daemon_config_path, runtime_dir.as_deref())
}

fn resolve_cli_socket_paths_with_runtime(
    legacy_socket: Option<&PathBuf>,
    daemon_config_path: &Path,
    runtime_dir: Option<&Path>,
) -> (PathBuf, PathBuf) {
    let default_operator = default_operator_socket(runtime_dir);
    let default_session = default_session_socket(runtime_dir);
    legacy_socket.map_or_else(
        || {
            if daemon_config_path.exists() {
                if let Ok(config) =
                    apm2_core::config::EcosystemConfig::from_file(daemon_config_path)
                {
                    (
                        normalize_operator_socket_path_with_runtime(
                            &config.daemon.operator_socket,
                            runtime_dir,
                        ),
                        normalize_session_socket_path_with_runtime(
                            &config.daemon.session_socket,
                            runtime_dir,
                        ),
                    )
                } else {
                    (default_operator, default_session)
                }
            } else {
                // RFC-0032::REQ-0244: Environment-based auto-config when no ecosystem.toml
                // exists.
                let env_config = apm2_core::config::EcosystemConfig::from_env();
                (
                    normalize_operator_socket_path_with_runtime(
                        &env_config.daemon.operator_socket,
                        runtime_dir,
                    ),
                    normalize_session_socket_path_with_runtime(
                        &env_config.daemon.session_socket,
                        runtime_dir,
                    ),
                )
            }
        },
        |socket| (socket.clone(), socket.clone()),
    )
}

const DEFAULT_CONFIG_FILE: &str = "ecosystem.toml";

fn resolve_daemon_config_path(config_path: &Path) -> PathBuf {
    resolve_daemon_config_path_with(config_path, resolve_git_common_dir)
}

fn resolve_daemon_config_path_with<F>(config_path: &Path, resolve_common_dir: F) -> PathBuf
where
    F: FnOnce() -> Option<PathBuf>,
{
    if config_path != Path::new(DEFAULT_CONFIG_FILE) {
        return config_path.to_path_buf();
    }

    let Some(common_dir) = resolve_common_dir() else {
        return config_path.to_path_buf();
    };

    if common_dir.file_name() != Some(OsStr::new(".git")) {
        return config_path.to_path_buf();
    }
    let Some(repo_root) = common_dir.parent() else {
        return config_path.to_path_buf();
    };

    let shared_config = repo_root.join(DEFAULT_CONFIG_FILE);
    if shared_config.exists() {
        shared_config
    } else {
        config_path.to_path_buf()
    }
}

fn resolve_git_common_dir() -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-common-dir"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let raw = stdout.trim();
    if raw.is_empty() {
        return None;
    }

    let path = PathBuf::from(raw);
    if path.is_absolute() {
        Some(path)
    } else {
        std::env::current_dir().ok().map(|cwd| cwd.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_daemon_config_path_prefers_shared_checkout_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_root = temp.path().join("repo");
        let common_git_dir = repo_root.join(".git");
        std::fs::create_dir_all(&common_git_dir).expect("create .git dir");
        let shared_config = repo_root.join(DEFAULT_CONFIG_FILE);
        std::fs::write(&shared_config, b"[daemon]\n").expect("write shared config");

        let resolved = resolve_daemon_config_path_with(Path::new(DEFAULT_CONFIG_FILE), || {
            Some(common_git_dir)
        });
        assert_eq!(resolved, shared_config);
    }

    #[test]
    fn resolve_daemon_config_path_falls_back_when_shared_config_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_root = temp.path().join("repo");
        let common_git_dir = repo_root.join(".git");
        std::fs::create_dir_all(&common_git_dir).expect("create .git dir");

        let resolved = resolve_daemon_config_path_with(Path::new(DEFAULT_CONFIG_FILE), || {
            Some(common_git_dir)
        });
        assert_eq!(resolved, PathBuf::from(DEFAULT_CONFIG_FILE));
    }

    #[test]
    fn resolve_daemon_config_path_keeps_non_default_config() {
        let resolved = resolve_daemon_config_path_with(Path::new("custom.toml"), || {
            Some(PathBuf::from("/tmp/repo/.git"))
        });
        assert_eq!(resolved, PathBuf::from("custom.toml"));
    }

    #[test]
    fn resolve_cli_socket_paths_ignores_tmp_config_when_xdg_runtime_is_available() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg_runtime = temp.path().join("xdg-runtime");
        std::fs::create_dir_all(&xdg_runtime).expect("create runtime dir");
        let config_path = temp.path().join("ecosystem.toml");
        std::fs::write(
            &config_path,
            "[daemon]\noperator_socket = \"/tmp/apm2/operator.sock\"\nsession_socket = \"/tmp/apm2/session.sock\"\n",
        )
        .expect("write config");
        let (operator, session) =
            resolve_cli_socket_paths_with_runtime(None, &config_path, Some(&xdg_runtime));
        assert_eq!(operator, xdg_runtime.join("apm2").join("operator.sock"));
        assert_eq!(session, xdg_runtime.join("apm2").join("session.sock"));
    }

    #[test]
    fn resolve_cli_socket_paths_expands_xdg_literal_config_values() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg_runtime = temp.path().join("xdg-runtime");
        std::fs::create_dir_all(&xdg_runtime).expect("create runtime dir");
        let config_path = temp.path().join("ecosystem.toml");
        std::fs::write(
            &config_path,
            "[daemon]\noperator_socket = \"$XDG_RUNTIME_DIR/apm2/op.sock\"\nsession_socket = \"$XDG_RUNTIME_DIR/apm2/sess.sock\"\n",
        )
        .expect("write config");
        let (operator, session) =
            resolve_cli_socket_paths_with_runtime(None, &config_path, Some(&xdg_runtime));
        assert_eq!(operator, xdg_runtime.join("apm2").join("op.sock"));
        assert_eq!(session, xdg_runtime.join("apm2").join("sess.sock"));
    }
}
