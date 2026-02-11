//! `apm2 fac pr auth-check` — verify GitHub App authentication.

use apm2_core::github::{GitHubAppTokenProvider, load_github_app_config};

use super::types::AuthInfo;
use crate::exit_codes::codes as exit_codes;

// ── CLI runner ─────────────────────────────────────────────────────────────

pub fn run_pr_auth_check(_repo: &str, json_output: bool) -> u8 {
    match local_auth_material_check() {
        Ok(info) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&info).unwrap_or_else(|_| "{}".to_string())
                );
            } else if info.login.is_empty() {
                println!("GitHub App auth material is configured.");
            } else {
                println!("GitHub App auth material is configured: {}", info.login);
            }
            exit_codes::SUCCESS
        },
        Err(error) => {
            super::output_pr_error(json_output, "pr_auth_check_failed", &error);
            exit_codes::GENERIC_ERROR
        },
    }
}

fn local_auth_material_check() -> Result<AuthInfo, String> {
    // Load persistent config file (may be None if not yet set up)
    let config = load_github_app_config();

    // Resolve app_id: env var → config file → error
    let app_id = env_or_config_str(
        "APM2_GITHUB_APP_ID",
        config.as_ref().map(|c| c.app_id.as_str()),
    )?;

    // Resolve installation_id: env var → config file → error
    let installation_id = env_or_config_str(
        "APM2_GITHUB_INSTALLATION_ID",
        config.as_ref().map(|c| c.installation_id.as_str()),
    )?;

    // Keyring service/account are optional; derived from app_id when absent
    let keyring_service = std::env::var("APM2_GITHUB_KEYRING_SERVICE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            config
                .as_ref()
                .and_then(|value| value.keyring_service.clone())
        });
    let keyring_account = std::env::var("APM2_GITHUB_KEYRING_ACCOUNT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            config
                .as_ref()
                .and_then(|value| value.keyring_account.clone())
        });
    let allow_file_fallback =
        env_bool("APM2_GITHUB_ALLOW_FILE_KEY_FALLBACK").unwrap_or_else(|| {
            config
                .as_ref()
                .and_then(|value| value.allow_private_key_file_fallback)
                .unwrap_or(false)
        });

    // Resolve private key: env var → keyring → optional file fallback.
    let _private_key = GitHubAppTokenProvider::resolve_private_key(
        &app_id,
        "APM2_GITHUB_APP_PRIVATE_KEY",
        config.as_ref(),
        keyring_service.as_deref(),
        keyring_account.as_deref(),
        allow_file_fallback,
    )
    .map_err(|error| format!("GitHub App credential setup failed: {error}"))?;

    Ok(AuthInfo {
        authenticated: true,
        login: format!("app:{app_id} installation:{installation_id}"),
    })
}

fn env_bool(name: &str) -> Option<bool> {
    let value = std::env::var(name).ok()?;
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Reads a value from the environment variable first; if empty/absent, falls
/// back to the config-file value. Returns an error if neither is available.
fn env_or_config_str(env_name: &str, config_value: Option<&str>) -> Result<String, String> {
    // 1. Env var
    if let Ok(value) = std::env::var(env_name) {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }

    // 2. Config file
    if let Some(val) = config_value {
        if !val.trim().is_empty() {
            return Ok(val.to_string());
        }
    }

    Err(format!(
        "missing {env_name}: set the env var or run `apm2 fac pr auth-setup`"
    ))
}
