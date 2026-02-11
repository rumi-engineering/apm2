//! Shared response types for `apm2 fac pr` subcommands.

use serde::{Deserialize, Serialize};

/// Forge provider authentication info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthInfo {
    pub authenticated: bool,
    pub login: String,
}
