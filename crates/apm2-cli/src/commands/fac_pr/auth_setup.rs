//! `apm2 fac pr auth-setup` — bootstrap GitHub App credentials.

use std::os::unix::fs::OpenOptionsExt;

use apm2_core::github::resolve_apm2_home;
use serde::Serialize;

use super::PrAuthSetupCliArgs;
use crate::exit_codes::codes as exit_codes;

#[derive(Debug, Serialize)]
struct AuthSetupResult {
    app_id: String,
    installation_id: String,
    keyring_service: String,
    keyring_account: String,
    private_key_stored: bool,
    source_file_deleted: bool,
    config_file: Option<String>,
}

pub fn run_pr_auth_setup(args: &PrAuthSetupCliArgs, json_output: bool) -> u8 {
    let keyring_account = args
        .keyring_account
        .clone()
        .unwrap_or_else(|| format!("app-{}", args.app_id));

    // ── Read PEM file ──────────────────────────────────────────────────────
    let private_key = match std::fs::read_to_string(&args.private_key_file) {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) => {
            super::output_pr_error(
                json_output,
                "pr_auth_setup_failed",
                "private key file is empty",
            );
            return exit_codes::GENERIC_ERROR;
        },
        Err(error) => {
            super::output_pr_error(
                json_output,
                "pr_auth_setup_failed",
                &format!(
                    "failed to read private key file {}: {error}",
                    args.private_key_file.display()
                ),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    // ── Store in keyring ───────────────────────────────────────────────────
    let entry = match keyring::Entry::new(&args.keyring_service, &keyring_account) {
        Ok(entry) => entry,
        Err(error) => {
            super::output_pr_error(
                json_output,
                "pr_auth_setup_failed",
                &format!("failed to initialize keyring entry: {error}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    if let Err(error) = entry.set_password(&private_key) {
        super::output_pr_error(
            json_output,
            "pr_auth_setup_failed",
            &format!("failed to store private key in keyring: {error}"),
        );
        return exit_codes::GENERIC_ERROR;
    }

    // ── Write persistent config file ───────────────────────────────────────
    let config_file = match write_config_and_pem(args, &keyring_account, &private_key) {
        Ok(path) => Some(path),
        Err(error) => {
            // Non-fatal: keyring succeeded, config file is a convenience fallback
            eprintln!("Warning: config file write failed: {error}");
            None
        },
    };

    // ── Optionally delete source PEM ───────────────────────────────────────
    let mut deleted = false;
    if !args.keep_private_key_file {
        match std::fs::remove_file(&args.private_key_file) {
            Ok(()) => {
                deleted = true;
            },
            Err(error) => {
                super::output_pr_error(
                    json_output,
                    "pr_auth_setup_failed",
                    &format!(
                        "private key stored, but failed to delete source file {}: {error}",
                        args.private_key_file.display()
                    ),
                );
                return exit_codes::GENERIC_ERROR;
            },
        }
    }

    // ── Output result ──────────────────────────────────────────────────────
    let result = AuthSetupResult {
        app_id: args.app_id.clone(),
        installation_id: args.installation_id.clone(),
        keyring_service: args.keyring_service.clone(),
        keyring_account,
        private_key_stored: true,
        source_file_deleted: deleted,
        config_file: config_file.clone(),
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("GitHub App private key stored in OS keyring.");
        if let Some(ref path) = config_file {
            println!("Config written to: {path}");
            println!("  No env vars needed — auth-check will read this file.");
        } else {
            println!(
                "Set environment for runtime:\n  \
                 export APM2_GITHUB_APP_ID={}\n  \
                 export APM2_GITHUB_INSTALLATION_ID={}\n  \
                 export APM2_GITHUB_KEYRING_SERVICE={}\n  \
                 export APM2_GITHUB_KEYRING_ACCOUNT={}",
                result.app_id,
                result.installation_id,
                result.keyring_service,
                result.keyring_account,
            );
        }
        if result.source_file_deleted {
            println!("Deleted source private key file after keyring import.");
        }
    }

    exit_codes::SUCCESS
}

/// Writes `~/.apm2/github_app.toml` and copies the PEM to
/// `~/.apm2/app-{app_id}.pem`.
///
/// Returns the path to the config file on success.
fn write_config_and_pem(
    args: &PrAuthSetupCliArgs,
    _keyring_account: &str,
    private_key_content: &str,
) -> Result<String, String> {
    let apm2_home = resolve_apm2_home()
        .ok_or_else(|| "cannot determine home directory for ~/.apm2".to_string())?;

    std::fs::create_dir_all(&apm2_home)
        .map_err(|e| format!("failed to create {}: {e}", apm2_home.display()))?;

    // Determine PEM destination path
    let pem_dest = if args.keep_private_key_file {
        // Point config at the original file location
        std::fs::canonicalize(&args.private_key_file)
            .map_err(|e| format!("failed to resolve PEM path: {e}"))?
    } else {
        // Copy PEM into ~/.apm2/app-{app_id}.pem with restrictive perms
        let dest = apm2_home.join(format!("app-{}.pem", args.app_id));
        write_file_mode_0600(&dest, private_key_content)?;
        dest
    };

    // Write github_app.toml
    let config_path = apm2_home.join("github_app.toml");
    let toml_content = format!(
        "app_id = \"{}\"\ninstallation_id = \"{}\"\nprivate_key_file = \"{}\"\n",
        args.app_id,
        args.installation_id,
        pem_dest.display(),
    );
    std::fs::write(&config_path, toml_content)
        .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;

    Ok(config_path.display().to_string())
}

/// Writes `content` to `path` with Unix file mode 0600.
fn write_file_mode_0600(path: &std::path::Path, content: &str) -> Result<(), String> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("failed to create {}: {e}", path.display()))?;

    file.write_all(content.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;

    Ok(())
}
