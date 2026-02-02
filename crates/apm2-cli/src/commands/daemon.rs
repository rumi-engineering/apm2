//! Daemon management commands.
//!
//! # TCK-00281: Legacy JSON IPC Removed
//!
//! Per DD-009 (RFC-0017), legacy JSON IPC has been removed from the daemon.
//! The `kill` command is stubbed out pending CLI migration to protobuf.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use tracing::info;

/// Start the daemon.
pub fn run(config: &Path, no_daemon: bool) -> Result<()> {
    let mut cmd = Command::new("apm2-daemon");
    cmd.arg("--config").arg(config);

    if no_daemon {
        cmd.arg("--no-daemon");
    }

    info!("Starting apm2 daemon...");

    if no_daemon {
        // Run in foreground
        let status = cmd.status().context("failed to start daemon")?;
        if !status.success() {
            bail!("daemon exited with error");
        }
    } else {
        // Run in background
        cmd.spawn().context("failed to start daemon")?;
        println!("apm2 daemon started");
    }

    Ok(())
}

/// Kill the daemon.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009. The CLI must be migrated to
/// protobuf-based communication. Until then, this command cannot send the
/// shutdown signal to the daemon.
pub fn kill(_socket_path: &Path) -> Result<()> {
    bail!(
        "CLI requires protobuf migration (DD-009). Legacy JSON IPC has been removed.\n\
         To stop the daemon, use: kill $(cat /run/apm2/apm2d.pid) or signal SIGTERM"
    );
}
