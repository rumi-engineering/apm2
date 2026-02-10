//! `apm2 fac pr auth-check` — verify GitHub App authentication.

use apm2_core::github::GitHubAppTokenProvider;

use super::client::GitHubPrClient;
use super::types::AuthInfo;
use crate::exit_codes::codes as exit_codes;

// ── Library function ───────────────────────────────────────────────────────

impl GitHubPrClient {
    /// Validate auth for the configured repository provider.
    pub fn auth_check(&self) -> Result<AuthInfo, String> {
        let info = self
            .provider()
            .auth_check()
            .map_err(|error| error.to_string())?;

        Ok(AuthInfo {
            authenticated: true,
            login: info.principal,
        })
    }
}

// ── CLI runner ─────────────────────────────────────────────────────────────

pub fn run_pr_auth_check(repo: &str, json_output: bool) -> u8 {
    let _ = repo;
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
    let app_id = required_env_nonempty("APM2_GITHUB_APP_ID")?;
    let installation_id = required_env_nonempty("APM2_GITHUB_INSTALLATION_ID")?;
    let keyring_service = std::env::var("APM2_GITHUB_KEYRING_SERVICE")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let keyring_account = std::env::var("APM2_GITHUB_KEYRING_ACCOUNT")
        .ok()
        .filter(|value| !value.trim().is_empty());

    let _private_key = GitHubAppTokenProvider::load_private_key_from_env_or_keyring(
        &app_id,
        "APM2_GITHUB_APP_PRIVATE_KEY",
        keyring_service.as_deref(),
        keyring_account.as_deref(),
    )
    .map_err(|error| format!("GitHub App credential setup failed: {error}"))?;

    Ok(AuthInfo {
        authenticated: true,
        login: format!("app:{app_id} installation:{installation_id}"),
    })
}

fn required_env_nonempty(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("missing required environment variable {name}"))
}
