//! Credential management commands.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result, bail};
use apm2_core::ipc::{IpcRequest, IpcResponse};

/// List credential profiles.
pub fn list(socket_path: &Path) -> Result<()> {
    let request = IpcRequest::ListCredentials;

    match send_request(socket_path, &request)? {
        IpcResponse::CredentialList { profiles } => {
            if profiles.is_empty() {
                println!("No credential profiles configured");
                return Ok(());
            }

            // Header
            println!(
                "{:<20} {:<12} {:<15} {:<20} {:<20}",
                "ID", "PROVIDER", "AUTH METHOD", "EXPIRES", "LAST USED"
            );
            println!("{}", "-".repeat(87));

            // Rows
            for profile in profiles {
                let expires = profile.expires_at.map_or_else(
                    || "N/A".to_string(),
                    |t| t.format("%Y-%m-%d %H:%M").to_string(),
                );
                let last_used = profile.last_used_at.map_or_else(
                    || "Never".to_string(),
                    |t| t.format("%Y-%m-%d %H:%M").to_string(),
                );

                println!(
                    "{:<20} {:<12} {:<15} {:<20} {:<20}",
                    truncate(&profile.id, 20),
                    profile.provider,
                    profile.auth_method,
                    expires,
                    last_used,
                );
            }
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to list credentials: {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Add a new credential profile.
pub fn add(socket_path: &Path, profile_id: &str, provider: &str, auth_method: &str) -> Result<()> {
    let request = IpcRequest::AddCredential {
        profile_id: profile_id.to_string(),
        provider: provider.to_string(),
        auth_method: auth_method.to_string(),
    };

    match send_request(socket_path, &request)? {
        IpcResponse::Ok { message } => {
            println!(
                "Created credential profile '{profile_id}'{}",
                message.map(|m| format!(": {m}")).unwrap_or_default()
            );
            println!();
            println!("Next steps:");
            println!("  1. Store your credentials securely:");
            println!("     apm2 creds login {provider} --profile-id {profile_id}");
            println!("  2. Or manually add to OS keyring");
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to add credential profile: {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Remove a credential profile.
pub fn remove(socket_path: &Path, profile_id: &str) -> Result<()> {
    let request = IpcRequest::RemoveCredential {
        profile_id: profile_id.to_string(),
    };

    match send_request(socket_path, &request)? {
        IpcResponse::Ok { message } => {
            println!(
                "Removed credential profile '{profile_id}'{}",
                message.map(|m| format!(": {m}")).unwrap_or_default()
            );
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to remove credential profile: {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Force refresh a credential profile.
pub fn refresh(socket_path: &Path, profile_id: &str) -> Result<()> {
    let request = IpcRequest::RefreshCredential {
        profile_id: profile_id.to_string(),
    };

    match send_request(socket_path, &request)? {
        IpcResponse::Ok { message } => {
            println!(
                "Refreshed credential profile '{profile_id}'{}",
                message.map(|m| format!(": {m}")).unwrap_or_default()
            );
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to refresh credential profile: {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Switch credentials for a running process.
pub fn switch(socket_path: &Path, process: &str, profile: &str) -> Result<()> {
    let request = IpcRequest::SwitchCredential {
        process_name: process.to_string(),
        profile_id: profile.to_string(),
    };

    match send_request(socket_path, &request)? {
        IpcResponse::Ok { message } => {
            println!(
                "Switched credentials for '{process}' to profile '{profile}'{}",
                message.map(|m| format!(": {m}")).unwrap_or_default()
            );
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to switch credentials: {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Interactive login flow.
#[allow(clippy::unnecessary_wraps)] // Returns Result for consistency with other commands
pub fn login(provider: &str, profile_id: Option<&str>) -> Result<()> {
    let profile = profile_id.unwrap_or(provider);

    println!("Starting interactive login for {provider}...");
    println!();

    match provider.to_lowercase().as_str() {
        "claude" => {
            println!("Claude login options:");
            println!();
            println!("1. API Key (recommended for programmatic access):");
            println!("   - Get an API key from https://console.anthropic.com/");
            println!("   - Set ANTHROPIC_API_KEY environment variable");
            println!();
            println!("2. Session Token (for Claude Code CLI):");
            println!("   - Run 'claude' to authenticate via browser");
            println!("   - Session will be stored automatically");
            println!();
            println!("To store credentials, use:");
            println!("  export ANTHROPIC_API_KEY=sk-ant-...");
            println!("  apm2 creds add {profile} --provider claude --auth-method api_key");
        },
        "gemini" => {
            println!("Gemini login options:");
            println!();
            println!("1. API Key:");
            println!("   - Get an API key from https://aistudio.google.com/");
            println!("   - Set GEMINI_API_KEY environment variable");
            println!();
            println!("2. OAuth (for Gemini CLI):");
            println!("   - Run 'gemini auth login' to authenticate via browser");
            println!();
            println!("To store credentials, use:");
            println!("  export GEMINI_API_KEY=...");
            println!("  apm2 creds add {profile} --provider gemini --auth-method api_key");
        },
        "openai" => {
            println!("OpenAI login options:");
            println!();
            println!("1. API Key:");
            println!("   - Get an API key from https://platform.openai.com/api-keys");
            println!("   - Set OPENAI_API_KEY environment variable");
            println!();
            println!("To store credentials, use:");
            println!("  export OPENAI_API_KEY=sk-...");
            println!("  apm2 creds add {profile} --provider openai --auth-method api_key");
        },
        _ => {
            println!("Unknown provider: {provider}");
            println!();
            println!("Supported providers: claude, gemini, openai");
        },
    }

    Ok(())
}

/// Truncate string to max length.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Send an IPC request to the daemon.
fn send_request(socket_path: &Path, request: &IpcRequest) -> Result<IpcResponse> {
    // Connect to daemon
    let mut stream = UnixStream::connect(socket_path)
        .context("failed to connect to daemon socket (is the daemon running?)")?;

    // Send request
    let request_json = serde_json::to_vec(&request)?;
    let framed = apm2_core::ipc::frame_message(&request_json);
    stream.write_all(&framed)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response_buf = vec![0u8; len];
    stream.read_exact(&mut response_buf)?;

    let response: IpcResponse = serde_json::from_slice(&response_buf)?;
    Ok(response)
}
