//! Credential management commands.
//!
//! # TCK-00343: Protocol Migration Complete
//!
//! Per RFC-0018 and DD-009, all credential management commands now use
//! `OperatorClient` with protobuf-based IPC via operator.sock.
//!
//! # Security
//!
//! - Credential operations are privileged and require operator.sock (mode 0600)
//! - Credential secrets are never logged or exposed in error messages
//! - All IPC uses tag-based protobuf framing (no JSON)

use std::path::Path;

use anyhow::{Context, Result};

use crate::client::protocol::OperatorClient;

/// Parse provider string to protocol enum value.
fn parse_provider(provider: &str) -> Result<i32> {
    use apm2_daemon::protocol::CredentialProvider;

    match provider.to_lowercase().as_str() {
        "github" => Ok(CredentialProvider::Github.into()),
        "anthropic" => Ok(CredentialProvider::Anthropic.into()),
        "openai" => Ok(CredentialProvider::Openai.into()),
        "api_key" | "apikey" | "api-key" => Ok(CredentialProvider::ApiKey.into()),
        _ => anyhow::bail!(
            "unknown provider: {provider}. Valid providers: github, anthropic, openai, api_key"
        ),
    }
}

/// Parse auth method string to protocol enum value.
fn parse_auth_method(auth_method: &str) -> Result<i32> {
    use apm2_daemon::protocol::CredentialAuthMethod;

    match auth_method.to_lowercase().as_str() {
        "oauth" => Ok(CredentialAuthMethod::Oauth.into()),
        "pat" => Ok(CredentialAuthMethod::Pat.into()),
        "api_key" | "apikey" | "api-key" => Ok(CredentialAuthMethod::ApiKey.into()),
        "ssh" => Ok(CredentialAuthMethod::Ssh.into()),
        _ => anyhow::bail!(
            "unknown auth method: {auth_method}. Valid methods: oauth, pat, api_key, ssh"
        ),
    }
}

/// Format provider enum value to display string.
fn format_provider(provider: i32) -> &'static str {
    use apm2_daemon::protocol::CredentialProvider;

    match CredentialProvider::try_from(provider) {
        Ok(CredentialProvider::Github) => "GitHub",
        Ok(CredentialProvider::Anthropic) => "Anthropic",
        Ok(CredentialProvider::Openai) => "OpenAI",
        Ok(CredentialProvider::ApiKey) => "API Key",
        _ => "Unknown",
    }
}

/// Format auth method enum value to display string.
fn format_auth_method(auth_method: i32) -> &'static str {
    use apm2_daemon::protocol::CredentialAuthMethod;

    match CredentialAuthMethod::try_from(auth_method) {
        Ok(CredentialAuthMethod::Oauth) => "OAuth",
        Ok(CredentialAuthMethod::Pat) => "PAT",
        Ok(CredentialAuthMethod::ApiKey) => "API Key",
        Ok(CredentialAuthMethod::Ssh) => "SSH",
        _ => "Unknown",
    }
}

/// List credential profiles.
///
/// # TCK-00343: `OperatorClient` Implementation
///
/// Uses `OperatorClient.list_credentials()` via operator.sock.
pub fn list(socket_path: &Path) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .list_credentials(None) // No provider filter
            .await
            .context("failed to list credentials")?;

        if response.profiles.is_empty() {
            println!("No credential profiles configured.");
        } else {
            println!("Credential profiles ({} total):\n", response.total_count);
            for profile in &response.profiles {
                let status = if profile.is_active {
                    "active"
                } else {
                    "inactive"
                };
                let display = if profile.display_name.is_empty() {
                    &profile.profile_id
                } else {
                    &profile.display_name
                };
                println!("  {display} [{status}]");
                println!(
                    "    ID: {}, Provider: {}, Auth: {}",
                    profile.profile_id,
                    format_provider(profile.provider),
                    format_auth_method(profile.auth_method)
                );
                if profile.expires_at > 0 {
                    println!("    Expires: {}", profile.expires_at);
                }
                println!();
            }
        }

        Ok(())
    })
}

/// Add a new credential profile.
///
/// # TCK-00343: `OperatorClient` Implementation
///
/// Uses `OperatorClient.add_credential()` via operator.sock.
///
/// # Security
///
/// The credential secret is read from stdin or environment, never from
/// command-line arguments to prevent exposure in shell history.
pub fn add(socket_path: &Path, profile_id: &str, provider: &str, auth_method: &str) -> Result<()> {
    let provider_enum = parse_provider(provider)?;
    let auth_method_enum = parse_auth_method(auth_method)?;

    // Security: Read secret from environment variable or prompt
    // Never accept secrets as command-line arguments
    let credential_secret = std::env::var("APM2_CREDENTIAL_SECRET").context(
        "APM2_CREDENTIAL_SECRET environment variable not set. \
                  Set this variable to the credential value (token, API key, etc.) \
                  before running this command.",
    )?;

    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .add_credential(
                profile_id,
                provider_enum,
                auth_method_enum,
                credential_secret.as_bytes(),
                profile_id, // Use profile_id as display name
                0,          // No expiration
            )
            .await
            .context("failed to add credential")?;

        if let Some(profile) = response.profile {
            println!(
                "Credential profile '{}' added successfully.",
                profile.profile_id
            );
            println!(
                "  Provider: {}, Auth: {}",
                format_provider(profile.provider),
                format_auth_method(profile.auth_method)
            );
        } else {
            println!("Credential profile added (no profile metadata returned).");
        }

        Ok(())
    })
}

/// Remove a credential profile.
///
/// # TCK-00343: `OperatorClient` Implementation
///
/// Uses `OperatorClient.remove_credential()` via operator.sock.
pub fn remove(socket_path: &Path, profile_id: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .remove_credential(profile_id)
            .await
            .context("failed to remove credential")?;

        if response.removed {
            println!("Credential profile '{profile_id}' removed successfully.");
        } else {
            println!("Credential profile '{profile_id}' was not found.");
        }

        Ok(())
    })
}

/// Refresh a credential profile.
///
/// # TCK-00343: `OperatorClient` Implementation
///
/// Uses `OperatorClient.refresh_credential()` via operator.sock.
/// Only applicable for OAuth credentials that support token refresh.
pub fn refresh(socket_path: &Path, profile_id: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .refresh_credential(profile_id)
            .await
            .context("failed to refresh credential")?;

        if let Some(profile) = response.profile {
            println!(
                "Credential profile '{}' refreshed successfully.",
                profile.profile_id
            );
            if response.new_expires_at > 0 {
                println!("  New expiration: {}", response.new_expires_at);
            }
        } else {
            println!("Credential refresh completed (no profile metadata returned).");
        }

        Ok(())
    })
}

/// Switch credentials for a running process.
///
/// # TCK-00343: `OperatorClient` Implementation
///
/// Uses `OperatorClient.switch_credential()` via operator.sock.
pub fn switch(socket_path: &Path, process_name: &str, profile_id: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .switch_credential(process_name, profile_id)
            .await
            .context("failed to switch credential")?;

        if response.success {
            println!("Switched credential for '{process_name}' to profile '{profile_id}'.");
            if !response.previous_profile_id.is_empty() {
                println!("  Previous profile: {}", response.previous_profile_id);
            }
        } else {
            println!("Failed to switch credential for '{process_name}'.");
        }

        Ok(())
    })
}

/// Show credential details.
///
/// # TCK-00343: `OperatorClient` Implementation
///
/// Uses `OperatorClient.list_credentials()` and filters by `profile_id`.
/// Secrets are never shown.
#[allow(dead_code)]
pub fn show(socket_path: &Path, profile_id: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .list_credentials(None)
            .await
            .context("failed to list credentials")?;

        let profile = response
            .profiles
            .iter()
            .find(|p| p.profile_id == profile_id);

        match profile {
            Some(p) => {
                println!("Credential Profile: {}", p.profile_id);
                println!("  Display Name: {}", p.display_name);
                println!("  Provider: {}", format_provider(p.provider));
                println!("  Auth Method: {}", format_auth_method(p.auth_method));
                println!(
                    "  Status: {}",
                    if p.is_active { "Active" } else { "Inactive" }
                );
                println!("  Created: {}", p.created_at);
                if p.expires_at > 0 {
                    println!("  Expires: {}", p.expires_at);
                } else {
                    println!("  Expires: Never");
                }
            },
            None => {
                println!("Credential profile '{profile_id}' not found.");
            },
        }

        Ok(())
    })
}

/// Interactive login for a provider.
///
/// # TCK-00343: `OperatorClient` Implementation
///
/// Uses `OperatorClient.login_credential()` via operator.sock.
/// For OAuth providers, this may return a URL to open in a browser.
pub fn login(socket_path: &Path, provider: &str, profile_id: Option<&str>) -> Result<()> {
    let provider_enum = parse_provider(provider)?;

    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .login_credential(
                provider_enum,
                profile_id,
                profile_id.unwrap_or("default"), // Display name
            )
            .await
            .context("failed to initiate login")?;

        if let Some(profile) = response.profile {
            if response.completed {
                println!(
                    "Login completed successfully for profile '{}'.",
                    profile.profile_id
                );
            } else if !response.login_url.is_empty() {
                println!("Please open the following URL in your browser to complete login:");
                println!("\n  {}\n", response.login_url);
                println!(
                    "Profile '{}' will be activated after login completes.",
                    profile.profile_id
                );
            } else {
                println!(
                    "Login initiated for profile '{}'. Awaiting completion.",
                    profile.profile_id
                );
            }
        } else {
            println!("Login initiated (no profile metadata returned).");
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_provider() {
        use apm2_daemon::protocol::CredentialProvider;

        assert_eq!(
            parse_provider("github").unwrap(),
            i32::from(CredentialProvider::Github)
        );
        assert_eq!(
            parse_provider("GITHUB").unwrap(),
            i32::from(CredentialProvider::Github)
        );
        assert_eq!(
            parse_provider("anthropic").unwrap(),
            i32::from(CredentialProvider::Anthropic)
        );
        assert_eq!(
            parse_provider("openai").unwrap(),
            i32::from(CredentialProvider::Openai)
        );
        assert_eq!(
            parse_provider("api_key").unwrap(),
            i32::from(CredentialProvider::ApiKey)
        );
        assert!(parse_provider("invalid").is_err());
    }

    #[test]
    fn test_parse_auth_method() {
        use apm2_daemon::protocol::CredentialAuthMethod;

        assert_eq!(
            parse_auth_method("oauth").unwrap(),
            i32::from(CredentialAuthMethod::Oauth)
        );
        assert_eq!(
            parse_auth_method("pat").unwrap(),
            i32::from(CredentialAuthMethod::Pat)
        );
        assert_eq!(
            parse_auth_method("api_key").unwrap(),
            i32::from(CredentialAuthMethod::ApiKey)
        );
        assert_eq!(
            parse_auth_method("ssh").unwrap(),
            i32::from(CredentialAuthMethod::Ssh)
        );
        assert!(parse_auth_method("invalid").is_err());
    }

    #[test]
    fn test_format_provider() {
        use apm2_daemon::protocol::CredentialProvider;

        assert_eq!(format_provider(CredentialProvider::Github.into()), "GitHub");
        assert_eq!(
            format_provider(CredentialProvider::Anthropic.into()),
            "Anthropic"
        );
        assert_eq!(format_provider(CredentialProvider::Openai.into()), "OpenAI");
        assert_eq!(
            format_provider(CredentialProvider::ApiKey.into()),
            "API Key"
        );
        assert_eq!(format_provider(999), "Unknown");
    }

    #[test]
    fn test_format_auth_method() {
        use apm2_daemon::protocol::CredentialAuthMethod;

        assert_eq!(
            format_auth_method(CredentialAuthMethod::Oauth.into()),
            "OAuth"
        );
        assert_eq!(format_auth_method(CredentialAuthMethod::Pat.into()), "PAT");
        assert_eq!(
            format_auth_method(CredentialAuthMethod::ApiKey.into()),
            "API Key"
        );
        assert_eq!(format_auth_method(CredentialAuthMethod::Ssh.into()), "SSH");
        assert_eq!(format_auth_method(999), "Unknown");
    }
}
