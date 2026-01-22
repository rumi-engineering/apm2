//! Credential management module.
//!
//! This module handles secure storage, retrieval, and hot-swapping of
//! credentials for AI CLI tools like Claude Code, Gemini CLI, and Codex CLI.

mod hotswap;
mod profile;
mod refresh;
mod store;

use std::path::PathBuf;

pub use hotswap::{HotSwapConfig, HotSwapError, HotSwapManager, HotSwapState};
pub use profile::{AuthMethod, CredentialProfile, CredentialProfileMetadata, ProfileId, Provider};
pub use refresh::{RefreshConfig, RefreshError, RefreshManager, RefreshState};
use serde::{Deserialize, Serialize};
pub use store::{CredentialStore, CredentialStoreError};

/// Credential binding configuration for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    /// Profile ID to use.
    pub profile: String,

    /// Enable hot-swapping.
    #[serde(default)]
    pub hot_swap: bool,

    /// Signal to use for hot-swap notification.
    #[serde(default = "default_hot_swap_signal")]
    pub hot_swap_signal: String,

    /// Enable automatic token refresh.
    #[serde(default)]
    pub auto_refresh: bool,

    /// Environment variable mappings (profile field -> env var name).
    #[serde(default)]
    pub env_mapping: std::collections::HashMap<String, String>,

    /// Config file path to update on credential change.
    #[serde(default)]
    pub config_file: Option<PathBuf>,
}

fn default_hot_swap_signal() -> String {
    "SIGHUP".to_string()
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            profile: String::new(),
            hot_swap: false,
            hot_swap_signal: default_hot_swap_signal(),
            auto_refresh: false,
            env_mapping: std::collections::HashMap::new(),
            config_file: None,
        }
    }
}

/// Credential-related errors.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// Profile not found.
    #[error("credential profile not found: {0}")]
    ProfileNotFound(String),

    /// Storage error.
    #[error("credential storage error: {0}")]
    Storage(#[from] CredentialStoreError),

    /// Hot-swap failed.
    #[error("credential hot-swap failed: {0}")]
    HotSwapFailed(String),

    /// Token refresh failed.
    #[error("token refresh failed: {0}")]
    RefreshFailed(String),

    /// Invalid credentials.
    #[error("invalid credentials: {0}")]
    Invalid(String),
}
