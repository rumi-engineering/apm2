//! CLI command implementations.

// =============================================================================
// Session Token Environment Variable (CWE-214 Mitigation)
// =============================================================================

/// Environment variable name for session token.
///
/// **Security (CWE-214 Mitigation)**: Using an environment variable instead of
/// a CLI argument prevents the session token from being visible in process
/// listings (`ps`, `/proc/[pid]/cmdline`).
///
/// Session-scoped commands (`tool request`, `event emit`, `evidence publish`,
/// `episode session-status`) accept the session token via either:
/// 1. **Preferred**: `APM2_SESSION_TOKEN` environment variable
/// 2. **Deprecated**: `--session-token` CLI flag (visible in process listings)
///
/// # Example
///
/// ```bash
/// # Secure: token not visible in `ps` output
/// export APM2_SESSION_TOKEN="sess_abc123..."
/// apm2 tool request --tool-id file_read --arguments '{}'
///
/// # Insecure: token visible via `ps aux | grep apm2`
/// apm2 tool request --session-token "sess_abc123..." --tool-id file_read
/// ```
///
/// # Reference
///
/// - CWE-214: Invocation of Process Using Visible Sensitive Information
/// - `documents/security/SECRETS_MANAGEMENT.cac.json`: "secrets are not passed
///   via command-line arguments"
// Note: This constant is not used programmatically (clap's `env` attribute reads
// the env var directly). It is exposed for documentation and external callers.
#[allow(dead_code)]
pub const APM2_SESSION_TOKEN_ENV: &str = "APM2_SESSION_TOKEN";

pub mod cac;
pub mod capability;
pub mod consensus;
pub mod coordinate;
pub mod creds;
pub mod daemon;
pub mod episode;
pub mod event;
pub mod evidence;
pub mod export;
pub mod fac;
pub mod fac_bench;
pub mod fac_broker;
mod fac_gates_job;
pub mod fac_gc;
pub mod fac_job;
pub mod fac_key_material;
pub mod fac_permissions;
pub mod fac_pr;
pub mod fac_preflight;
pub mod fac_quarantine;
pub mod fac_queue;
mod fac_queue_submit;
pub mod fac_review;
pub mod fac_secure_io;
pub mod fac_utils;
pub mod fac_warm;
pub mod fac_worker;
pub mod factory;
pub mod pack;
pub mod process;
pub mod role_launch;
pub mod tool;
pub mod work;

#[cfg(test)]
pub fn env_var_test_lock() -> &'static std::sync::Mutex<()> {
    use std::sync::{Mutex, OnceLock};

    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}
