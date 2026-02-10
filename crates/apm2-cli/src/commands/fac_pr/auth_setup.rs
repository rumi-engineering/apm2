//! `apm2 fac pr auth-setup` — bootstrap GitHub App credentials.

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
}

pub fn run_pr_auth_setup(args: &PrAuthSetupCliArgs, json_output: bool) -> u8 {
    let keyring_account = args
        .keyring_account
        .clone()
        .unwrap_or_else(|| format!("app-{}", args.app_id));

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

    let result = AuthSetupResult {
        app_id: args.app_id.clone(),
        installation_id: args.installation_id.clone(),
        keyring_service: args.keyring_service.clone(),
        keyring_account,
        private_key_stored: true,
        source_file_deleted: deleted,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("GitHub App private key stored in OS keyring.");
        println!(
            "Set environment for runtime:\n  export APM2_GITHUB_APP_ID={}\n  export APM2_GITHUB_INSTALLATION_ID={}\n  export APM2_GITHUB_KEYRING_SERVICE={}\n  export APM2_GITHUB_KEYRING_ACCOUNT={}",
            result.app_id, result.installation_id, result.keyring_service, result.keyring_account,
        );
        if result.source_file_deleted {
            println!("Deleted source private key file after keyring import.");
        }
    }

    exit_codes::SUCCESS
}
