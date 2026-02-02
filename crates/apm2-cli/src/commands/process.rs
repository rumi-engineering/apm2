//! Process management commands.
//!
//! # TCK-00281: Legacy JSON IPC Removed
//!
//! Per DD-009 (RFC-0017), legacy JSON IPC has been removed from the daemon.
//! All process management commands are stubbed out pending CLI migration to
//! protobuf.

use std::path::Path;

use anyhow::{Result, bail};

/// Protocol migration error message.
const MIGRATION_ERROR: &str =
    "CLI requires protobuf migration (DD-009). Legacy JSON IPC has been removed.";

/// Start a process.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn start(_socket_path: &Path, _name: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Stop a process.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn stop(_socket_path: &Path, _name: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Restart a process.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn restart(_socket_path: &Path, _name: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Graceful reload (rolling restart).
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn reload(_socket_path: &Path, _name: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// List all processes.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn list(_socket_path: &Path) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Show daemon status.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn status(_socket_path: &Path, _name: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Show process info.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
#[allow(dead_code)]
pub fn info(_socket_path: &Path, _name: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Tail process logs.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn logs(_socket_path: &Path, _name: &str, _lines: u32, _follow: bool) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}
