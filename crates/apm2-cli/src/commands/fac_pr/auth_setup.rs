//! `apm2 fac pr auth-setup` — bootstrap GitHub App credentials.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use apm2_core::github::resolve_apm2_home;
use secrecy::{ExposeSecret, SecretString};
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
    file_fallback_enabled: bool,
    fallback_private_key_file: Option<String>,
    source_file_deleted: bool,
    config_file: String,
}

#[derive(Debug)]
struct PersistedConfigResult {
    config_path: PathBuf,
    fallback_private_key_file: Option<PathBuf>,
}

pub fn run_pr_auth_setup(args: &PrAuthSetupCliArgs, json_output: bool) -> u8 {
    let keyring_account = args
        .keyring_account
        .clone()
        .unwrap_or_else(|| format!("app-{}", args.app_id));

    // ── Read PEM file ──────────────────────────────────────────────────────
    let private_key = match read_private_key_secret(&args.private_key_file) {
        Ok(value) => value,
        Err(error) => {
            super::output_pr_error(json_output, "pr_auth_setup_failed", &error);
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

    if let Err(error) = entry.set_password(private_key.expose_secret()) {
        super::output_pr_error(
            json_output,
            "pr_auth_setup_failed",
            &format!("failed to store private key in keyring: {error}"),
        );
        return exit_codes::GENERIC_ERROR;
    }

    // ── Write persistent config file ───────────────────────────────────────
    let persisted = match write_persistent_config(args, &keyring_account, &private_key) {
        Ok(value) => value,
        Err(error) => {
            super::output_pr_error(json_output, "pr_auth_setup_failed", &error);
            return exit_codes::GENERIC_ERROR;
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
        file_fallback_enabled: args.allow_private_key_file_fallback,
        fallback_private_key_file: persisted
            .fallback_private_key_file
            .as_ref()
            .map(|path| path.display().to_string()),
        source_file_deleted: deleted,
        config_file: persisted.config_path.display().to_string(),
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
    );

    exit_codes::SUCCESS
}

fn read_private_key_secret(path: &Path) -> Result<SecretString, String> {
    let content = std::fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read private key file {}: {error}",
            path.display()
        )
    })?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err("private key file is empty".to_string());
    }
    Ok(SecretString::new(trimmed.to_string().into_boxed_str()))
}

/// Writes `~/.apm2/github_app.toml` and, when explicitly requested, persists
/// a file-based fallback private key path.
fn write_persistent_config(
    args: &PrAuthSetupCliArgs,
    keyring_account: &str,
    private_key_content: &SecretString,
) -> Result<PersistedConfigResult, String> {
    let apm2_home = resolve_apm2_home()
        .ok_or_else(|| "cannot determine home directory for ~/.apm2".to_string())?;

    crate::commands::fac_permissions::ensure_dir_with_mode(&apm2_home)
        .map_err(|e| format!("failed to create {}: {e}", apm2_home.display()))?;

    let fallback_private_key_file = if args.allow_private_key_file_fallback {
        if args.keep_private_key_file {
            let canonical = std::fs::canonicalize(&args.private_key_file)
                .map_err(|e| format!("failed to resolve PEM path: {e}"))?;
            ensure_regular_file_no_symlink(&canonical)?;
            Some(canonical)
        } else {
            let dest = apm2_home.join(format!("app-{}.pem", args.app_id));
            crate::commands::fac_permissions::write_fac_file_with_mode(
                &dest,
                private_key_content.expose_secret().as_bytes(),
            )
            .map_err(|error| format!("failed to create {}: {error}", dest.display()))?;
            Some(dest)
        }
    } else {
        None
    };

    // Write github_app.toml
    let config_path = apm2_home.join("github_app.toml");
    let mut toml_content = format!(
        "app_id = \"{}\"\ninstallation_id = \"{}\"\nkeyring_service = \"{}\"\nkeyring_account = \"{}\"\nallow_private_key_file_fallback = {}\n",
        args.app_id,
        args.installation_id,
        args.keyring_service,
        keyring_account,
        args.allow_private_key_file_fallback,
    );
    if let Some(path) = fallback_private_key_file.as_ref() {
        writeln!(
            &mut toml_content,
            "private_key_file = \"{}\"",
            path.display()
        )
        .expect("infallible String write");
    }
    crate::commands::fac_permissions::write_fac_file_with_mode(
        &config_path,
        toml_content.as_bytes(),
    )
    .map_err(|error| format!("failed to create {}: {error}", config_path.display()))?;

    Ok(PersistedConfigResult {
        config_path,
        fallback_private_key_file,
    })
}

/// Writes `content` to `path` with Unix file mode 0600.
fn ensure_regular_file_no_symlink(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("failed to inspect {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing to use symlink target for private key path: {}",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "refusing to use non-regular file for private key path: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::ensure_regular_file_no_symlink;

    #[cfg(unix)]
    #[test]
    fn write_file_mode_0600_rejects_symlink_target() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(tmp.path(), PermissionsExt::from_mode(0o700))
            .expect("harden temp dir");
        let target = tmp.path().join("target.pem");
        fs::write(&target, "target").expect("seed target");
        let link = tmp.path().join("link.pem");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let err = ensure_regular_file_no_symlink(&link).expect_err("symlink must fail");
        assert!(err.contains("symlink"), "unexpected error: {err}");
    }
}
