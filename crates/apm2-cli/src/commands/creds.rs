//! Credential management commands.
//!
//! # TCK-00281: Legacy JSON IPC Removed
//!
//! Per DD-009 (RFC-0017), legacy JSON IPC has been removed from the daemon.
//! All credential management commands are stubbed out pending CLI migration to
//! protobuf.

use std::path::Path;

use anyhow::{Result, bail};

/// Protocol migration error message.
const MIGRATION_ERROR: &str =
    "CLI requires protobuf migration (DD-009). Legacy JSON IPC has been removed.";

/// List credential profiles.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn list(_socket_path: &Path) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Add a new credential profile.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn add(
    _socket_path: &Path,
    _profile_id: &str,
    _provider: &str,
    _auth_method: &str,
) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Remove a credential profile.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn remove(_socket_path: &Path, _profile_id: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Refresh a credential profile.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn refresh(_socket_path: &Path, _profile_id: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Switch credentials for a running process.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn switch(_socket_path: &Path, _process_name: &str, _profile_id: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Show credential details.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
#[allow(dead_code)]
pub fn show(_socket_path: &Path, _profile_id: &str) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}

/// Interactive login for a provider.
///
/// # TCK-00281: Stub Implementation
///
/// Legacy JSON IPC has been removed per DD-009.
pub fn login(_provider: &str, _profile_id: Option<&str>) -> Result<()> {
    bail!("{MIGRATION_ERROR}");
}
