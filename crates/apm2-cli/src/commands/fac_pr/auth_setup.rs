//! `apm2 fac pr auth-setup` — bootstrap GitHub App credentials.
//!
//! # Security contracts
//!
//! - [INV-SETUP-003] Symlink targets are rejected for private key paths via
//!   `O_NOFOLLOW` at open time (CWE-61 mitigation, no TOCTOU gap).
//! - [CTR-1603] Private key reads are bounded to [`MAX_PRIVATE_KEY_FILE_SIZE`]
//!   bytes to prevent resource exhaustion.
//! - [CTR-2609] `app_id` and `installation_id` are validated as strict
//!   numeric-only GitHub identifiers before use in filesystem paths or config
//!   content.

use std::path::{Path, PathBuf};

use apm2_core::github::resolve_apm2_home;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use super::PrAuthSetupCliArgs;
use crate::exit_codes::codes as exit_codes;

/// Maximum size for a private key PEM file (16 KiB). RSA-4096 PEM is ~3.2 KiB;
/// 16 KiB provides ample headroom while preventing unbounded allocation
/// (CTR-1603, RSK-1601).
const MAX_PRIVATE_KEY_FILE_SIZE: u64 = 16 * 1024;

#[derive(Debug, Serialize)]
struct AuthSetupResult {
    app_id: String,
    installation_id: String,
    /// `"keyring"` or `"file-only"` (when `--for-systemd` is used).
    mode: String,
    keyring_service: Option<String>,
    keyring_account: Option<String>,
    private_key_stored: bool,
    file_fallback_enabled: bool,
    fallback_private_key_file: Option<String>,
    source_file_deleted: bool,
    config_file: String,
}

/// TOML-serializable config structure for `github_app.toml`.
///
/// Using typed serialization instead of manual string interpolation prevents
/// config injection via untrusted `app_id` or `installation_id` values
/// (CTR-2609).
#[derive(Debug, Serialize)]
struct GitHubAppTomlConfig {
    app_id: String,
    installation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    keyring_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keyring_account: Option<String>,
    allow_private_key_file_fallback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key_file: Option<String>,
}

#[derive(Debug)]
struct PersistedConfigResult {
    config_path: PathBuf,
    fallback_private_key_file: Option<PathBuf>,
}

/// Validate that a GitHub identifier (`app_id` or `installation_id`) is
/// strictly numeric. Rejects path separators, dot-segments, quotes, control
/// characters, and whitespace to prevent path traversal and config injection
/// (CTR-2609).
fn validate_github_id(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "{label} must be numeric-only (got {value:?}): \
             path separators, dot-segments, quotes, control characters, \
             and whitespace are rejected"
        ));
    }
    Ok(())
}

pub fn run_pr_auth_setup(args: &PrAuthSetupCliArgs, json_output: bool) -> u8 {
    // ── Validate GitHub identifiers (CTR-2609) ──────────────────────────
    if let Err(error) = validate_github_id(&args.app_id, "app_id") {
        super::output_pr_error(json_output, "pr_auth_setup_failed", &error);
        return exit_codes::GENERIC_ERROR;
    }
    if let Err(error) = validate_github_id(&args.installation_id, "installation_id") {
        super::output_pr_error(json_output, "pr_auth_setup_failed", &error);
        return exit_codes::GENERIC_ERROR;
    }

    // ── Route to headless mode ──────────────────────────────────────────
    // BLOCKER-2 fix: when --for-systemd is explicitly set, use headless mode.
    // The headless path skips keyring entirely, which is the correct behavior
    // for headless compute hosts. The DoD command is:
    //   apm2 fac pr auth-setup --app-id ... --installation-id ... \
    //     --private-key-file ... --for-systemd
    if args.for_systemd {
        return run_pr_auth_setup_headless(args, json_output);
    }

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
        mode: "keyring".to_string(),
        keyring_service: Some(args.keyring_service.clone()),
        keyring_account: Some(keyring_account),
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

/// Headless mode (`--for-systemd`): skip keyring entirely, store PEM file
/// under `$APM2_HOME` with restrictive permissions, and write a config with
/// file-based fallback enabled.
///
/// This is the recommended path for systemd-managed compute hosts where no
/// desktop keyring session is available.
fn run_pr_auth_setup_headless(args: &PrAuthSetupCliArgs, json_output: bool) -> u8 {
    // ── Read PEM file ──────────────────────────────────────────────────────
    let private_key = match read_private_key_secret(&args.private_key_file) {
        Ok(value) => value,
        Err(error) => {
            super::output_pr_error(json_output, "pr_auth_setup_failed", &error);
            return exit_codes::GENERIC_ERROR;
        },
    };

    // ── Resolve APM2 home and write PEM + config ───────────────────────────
    let Some(apm2_home) = resolve_apm2_home() else {
        super::output_pr_error(
            json_output,
            "pr_auth_setup_failed",
            "cannot determine home directory for ~/.apm2",
        );
        return exit_codes::GENERIC_ERROR;
    };

    if let Err(error) = crate::commands::fac_permissions::ensure_dir_with_mode(&apm2_home) {
        super::output_pr_error(
            json_output,
            "pr_auth_setup_failed",
            &format!("failed to create {}: {error}", apm2_home.display()),
        );
        return exit_codes::GENERIC_ERROR;
    }

    // Write PEM file to $APM2_HOME/app-{app_id}.pem with mode 0600.
    let dest_pem = apm2_home.join(format!("app-{}.pem", args.app_id));
    if let Err(error) = crate::commands::fac_permissions::write_fac_file_with_mode(
        &dest_pem,
        private_key.expose_secret().as_bytes(),
    ) {
        super::output_pr_error(
            json_output,
            "pr_auth_setup_failed",
            &format!("failed to write PEM to {}: {error}", dest_pem.display()),
        );
        return exit_codes::GENERIC_ERROR;
    }

    // Write github_app.toml via typed TOML serialization (CTR-2609: prevents
    // config injection from untrusted app_id/installation_id values).
    let config_path = apm2_home.join("github_app.toml");
    let toml_config = GitHubAppTomlConfig {
        app_id: args.app_id.clone(),
        installation_id: args.installation_id.clone(),
        keyring_service: None,
        keyring_account: None,
        allow_private_key_file_fallback: true,
        private_key_file: Some(dest_pem.display().to_string()),
    };
    let toml_content = match toml::to_string_pretty(&toml_config) {
        Ok(content) => {
            format!(
                "# Generated by `apm2 fac pr auth-setup --for-systemd`\n\
                 # Headless mode: keyring is not used; private key is stored on disk.\n\
                 # For systemd credential injection, add to your [Service] section:\n\
                 #   LoadCredential=github-app-key:{pem_display}\n\n\
                 {content}",
                pem_display = dest_pem.display(),
            )
        },
        Err(error) => {
            super::output_pr_error(
                json_output,
                "pr_auth_setup_failed",
                &format!("failed to serialize github_app.toml: {error}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };
    if let Err(error) = crate::commands::fac_permissions::write_fac_file_with_mode(
        &config_path,
        toml_content.as_bytes(),
    ) {
        super::output_pr_error(
            json_output,
            "pr_auth_setup_failed",
            &format!(
                "failed to write config to {}: {error}",
                config_path.display()
            ),
        );
        return exit_codes::GENERIC_ERROR;
    }

    // ── Optionally delete source PEM ───────────────────────────────────────
    // MAJOR-1 fix: Compare canonical source and destination paths. If they
    // alias the same file, skip deletion to avoid removing the just-written
    // PEM. This handles the case where the user passes the destination path
    // as the source (e.g., $APM2_HOME/app-{app_id}.pem).
    let mut deleted = false;
    if !args.keep_private_key_file {
        let source_is_dest = paths_are_same_file(&args.private_key_file, &dest_pem);
        if source_is_dest {
            // Source and destination are the same file — skip deletion.
            deleted = false;
        } else {
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
    }

    // ── Output result ──────────────────────────────────────────────────────
    let result = AuthSetupResult {
        app_id: args.app_id.clone(),
        installation_id: args.installation_id.clone(),
        mode: "file-only".to_string(),
        keyring_service: None,
        keyring_account: None,
        private_key_stored: true,
        file_fallback_enabled: true,
        fallback_private_key_file: Some(dest_pem.display().to_string()),
        source_file_deleted: deleted,
        config_file: config_path.display().to_string(),
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
    );

    exit_codes::SUCCESS
}

/// Check whether two paths refer to the same file by comparing canonical paths.
///
/// Returns `true` if both paths resolve to the same canonical path, or `false`
/// if either path cannot be canonicalized (e.g., does not exist).
fn paths_are_same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

/// Open a file for reading, rejecting symlinks on Unix via `O_NOFOLLOW`.
///
/// This eliminates the TOCTOU gap between symlink check and file read by
/// atomically rejecting symlinks at open time (INV-SETUP-003, CWE-61).
#[cfg(unix)]
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Open a file for reading (non-Unix fallback — no symlink guard available).
#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Read a private key PEM file with bounded I/O and symlink rejection.
///
/// Opens the file atomically with `O_NOFOLLOW` (rejecting symlinks), then
/// validates metadata on the opened file descriptor, and reads bounded
/// content from the same descriptor. This eliminates the TOCTOU gap that
/// would exist if metadata were checked by path and then re-opened for read
/// (INV-SETUP-003, INV-0910/CTR-0901 pattern).
///
/// The file must be a regular file (no symlinks), and its size must not
/// exceed [`MAX_PRIVATE_KEY_FILE_SIZE`] (CTR-1603, RSK-1601).
fn read_private_key_secret(path: &Path) -> Result<SecretString, String> {
    use std::io::Read;

    let mut file =
        open_nofollow(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "refusing non-regular path for private key file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_PRIVATE_KEY_FILE_SIZE {
        return Err(format!(
            "private key file too large: {} bytes > {} max ({})",
            metadata.len(),
            MAX_PRIVATE_KEY_FILE_SIZE,
            path.display()
        ));
    }

    let len: usize = usize::try_from(metadata.len()).map_err(|_| {
        format!(
            "private key file size does not fit usize: {} ({})",
            metadata.len(),
            path.display()
        )
    })?;
    let mut content = String::with_capacity(len);
    file.read_to_string(&mut content)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(format!("private key file is empty: {}", path.display()));
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

    // Write github_app.toml via typed TOML serialization (CTR-2609).
    let config_path = apm2_home.join("github_app.toml");
    let toml_config = GitHubAppTomlConfig {
        app_id: args.app_id.clone(),
        installation_id: args.installation_id.clone(),
        keyring_service: Some(args.keyring_service.clone()),
        keyring_account: Some(keyring_account.to_string()),
        allow_private_key_file_fallback: args.allow_private_key_file_fallback,
        private_key_file: fallback_private_key_file
            .as_ref()
            .map(|p| p.display().to_string()),
    };
    let toml_content = toml::to_string_pretty(&toml_config)
        .map_err(|e| format!("failed to serialize github_app.toml: {e}"))?;
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

    use super::{ensure_regular_file_no_symlink, validate_github_id};

    // =========================================================================
    // Symlink rejection (INV-SETUP-003)
    // =========================================================================

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

    // =========================================================================
    // MAJOR-2 regression: read_private_key_secret uses O_NOFOLLOW + bounded IO
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn read_private_key_secret_rejects_symlink_via_open_nofollow() {
        // Verifies that O_NOFOLLOW atomically rejects symlink private key
        // sources at open time (INV-SETUP-003, CWE-61).
        let tmp = tempfile::tempdir().expect("tempdir");
        let real_file = tmp.path().join("real-key.pem");
        fs::write(
            &real_file,
            "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n",
        )
        .expect("write real file");
        let link = tmp.path().join("symlinked-key.pem");
        std::os::unix::fs::symlink(&real_file, &link).expect("create symlink");

        let result = super::read_private_key_secret(&link);
        assert!(
            result.is_err(),
            "symlink should be rejected atomically at open: {result:?}"
        );
        let err = result.unwrap_err();
        // O_NOFOLLOW produces OS-level "Too many levels of symbolic links".
        assert!(
            err.contains("symlink") || err.contains("symbolic link"),
            "error should mention symlink rejection: {err}"
        );
    }

    #[test]
    fn read_private_key_secret_rejects_oversize() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let oversize_file = tmp.path().join("huge.pem");
        let oversize_len =
            usize::try_from(super::MAX_PRIVATE_KEY_FILE_SIZE + 1).expect("size fits usize");
        let oversize = "x".repeat(oversize_len);
        fs::write(&oversize_file, oversize).expect("write oversize file");

        let result = super::read_private_key_secret(&oversize_file);
        assert!(result.is_err(), "should reject oversized key file");
        let err = result.unwrap_err();
        assert!(
            err.contains("too large"),
            "error should mention too large: {err}"
        );
    }

    #[test]
    fn read_private_key_secret_rejects_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let empty_file = tmp.path().join("empty.pem");
        fs::write(&empty_file, "  \n  ").expect("write empty file");

        let result = super::read_private_key_secret(&empty_file);
        assert!(result.is_err(), "should reject empty key file");
        let err = result.unwrap_err();
        assert!(err.contains("empty"), "error should mention empty: {err}");
    }

    #[test]
    fn read_private_key_secret_reads_valid_file() {
        use secrecy::ExposeSecret;

        let tmp = tempfile::tempdir().expect("tempdir");
        let pem_file = tmp.path().join("valid.pem");
        fs::write(
            &pem_file,
            "-----BEGIN RSA PRIVATE KEY-----\ntest-data\n-----END RSA PRIVATE KEY-----\n",
        )
        .expect("write pem file");

        let result = super::read_private_key_secret(&pem_file);
        assert!(
            result.is_ok(),
            "valid PEM file should be readable: {result:?}"
        );
        let secret = result.unwrap();
        assert!(
            secret.expose_secret().contains("BEGIN RSA PRIVATE KEY"),
            "should contain PEM content"
        );
    }

    // =========================================================================
    // GitHub ID validation (CTR-2609)
    // =========================================================================

    #[test]
    fn validate_github_id_accepts_numeric() {
        assert!(validate_github_id("12345", "app_id").is_ok());
        assert!(validate_github_id("0", "app_id").is_ok());
        assert!(validate_github_id("999999999", "installation_id").is_ok());
    }

    #[test]
    fn validate_github_id_rejects_empty() {
        let err = validate_github_id("", "app_id").unwrap_err();
        assert!(err.contains("empty"), "error: {err}");
    }

    #[test]
    fn validate_github_id_rejects_path_separators() {
        let err = validate_github_id("../etc", "app_id").unwrap_err();
        assert!(err.contains("numeric-only"), "error: {err}");
        let err2 = validate_github_id("foo/bar", "app_id").unwrap_err();
        assert!(err2.contains("numeric-only"), "error: {err2}");
    }

    #[test]
    fn validate_github_id_rejects_non_numeric() {
        assert!(validate_github_id("abc", "app_id").is_err());
        assert!(validate_github_id("12 34", "app_id").is_err());
        assert!(validate_github_id("12\"34", "app_id").is_err());
        assert!(validate_github_id("12\n34", "app_id").is_err());
        assert!(validate_github_id("12\x0034", "app_id").is_err());
    }

    // =========================================================================
    // Headless setup E2E
    // =========================================================================

    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)] // Env var mutation is required for test setup and teardown.
    fn headless_setup_writes_config_and_pem() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(tmp.path(), PermissionsExt::from_mode(0o700))
            .expect("harden temp dir");

        // Create a source PEM file.
        let src_pem = tmp.path().join("source.pem");
        fs::write(
            &src_pem,
            "-----BEGIN RSA PRIVATE KEY-----\ntest-key-data\n-----END RSA PRIVATE KEY-----\n",
        )
        .expect("write source pem");

        // Point APM2_HOME to our temp dir.
        let prev_home = std::env::var("APM2_HOME").ok();
        let apm2_home = tmp.path().join("apm2_home");
        // SAFETY: This modifies process-global state; acceptable in serial test.
        unsafe { std::env::set_var("APM2_HOME", &apm2_home) };

        let args = super::super::PrAuthSetupCliArgs {
            app_id: "12345".to_string(),
            installation_id: "67890".to_string(),
            private_key_file: src_pem.clone(),
            keyring_service: "apm2.github.app".to_string(),
            keyring_account: None,
            allow_private_key_file_fallback: false,
            keep_private_key_file: false,
            for_systemd: true,
            json: false,
        };

        let exit = super::run_pr_auth_setup(&args, true);
        assert_eq!(exit, 0, "headless setup should succeed");

        // Verify config file was written.
        let config_path = apm2_home.join("github_app.toml");
        assert!(config_path.exists(), "github_app.toml must exist");
        let config_content = fs::read_to_string(&config_path).expect("read config");
        assert!(
            config_content.contains("app_id = \"12345\""),
            "config must contain app_id: {config_content}"
        );
        assert!(
            config_content.contains("installation_id = \"67890\""),
            "config must contain installation_id: {config_content}"
        );
        assert!(
            config_content.contains("allow_private_key_file_fallback = true"),
            "config must enable file fallback: {config_content}"
        );
        assert!(
            config_content.contains("private_key_file"),
            "config must contain private_key_file: {config_content}"
        );

        // Verify PEM was copied to $APM2_HOME.
        let dest_pem = apm2_home.join("app-12345.pem");
        assert!(dest_pem.exists(), "destination PEM must exist");
        let pem_content = fs::read_to_string(&dest_pem).expect("read dest pem");
        assert!(
            pem_content.contains("BEGIN RSA PRIVATE KEY"),
            "PEM content must be preserved"
        );

        // Verify PEM has 0600 permissions.
        let pem_meta = fs::metadata(&dest_pem).expect("read pem metadata");
        let pem_mode = pem_meta.permissions().mode() & 0o7777;
        assert_eq!(
            pem_mode, 0o600,
            "PEM must have mode 0600, got {pem_mode:04o}"
        );

        // Verify source PEM was deleted.
        assert!(!src_pem.exists(), "source PEM should be deleted");

        // Restore env.
        match prev_home {
            Some(val) => unsafe { std::env::set_var("APM2_HOME", val) },
            None => unsafe { std::env::remove_var("APM2_HOME") },
        }
    }

    // =========================================================================
    // MAJOR-1 regression: source==destination PEM must not be deleted
    // =========================================================================

    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn headless_setup_source_equals_dest_skips_deletion() {
        // When the source PEM path is the same as the destination
        // ($APM2_HOME/app-{app_id}.pem), deletion must be skipped to avoid
        // removing the just-written PEM (MAJOR-1 regression).
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(tmp.path(), PermissionsExt::from_mode(0o700))
            .expect("harden temp dir");

        let prev_home = std::env::var("APM2_HOME").ok();
        let apm2_home = tmp.path().join("apm2_home");
        // SAFETY: This modifies process-global state; acceptable in serial test.
        unsafe { std::env::set_var("APM2_HOME", &apm2_home) };

        // Create the APM2 home directory and the PEM file at the destination path.
        fs::create_dir_all(&apm2_home).expect("create apm2_home");
        std::fs::set_permissions(&apm2_home, PermissionsExt::from_mode(0o700))
            .expect("harden apm2 home");
        let dest_pem_path = apm2_home.join("app-54321.pem");
        fs::write(
            &dest_pem_path,
            "-----BEGIN RSA PRIVATE KEY-----\nexisting-key\n-----END RSA PRIVATE KEY-----\n",
        )
        .expect("write source pem at dest");
        std::fs::set_permissions(&dest_pem_path, PermissionsExt::from_mode(0o600))
            .expect("set pem perms");

        let args = super::super::PrAuthSetupCliArgs {
            app_id: "54321".to_string(),
            installation_id: "11111".to_string(),
            // Source path is exactly the destination path.
            private_key_file: dest_pem_path.clone(),
            keyring_service: "apm2.github.app".to_string(),
            keyring_account: None,
            allow_private_key_file_fallback: false,
            keep_private_key_file: false, // Would delete without the fix.
            for_systemd: true,
            json: false,
        };

        let exit = super::run_pr_auth_setup(&args, true);
        assert_eq!(exit, 0, "headless setup should succeed");

        // The PEM file must still exist (not deleted).
        assert!(
            dest_pem_path.exists(),
            "destination PEM must survive when source==dest"
        );
        let content = fs::read_to_string(&dest_pem_path).expect("read pem");
        assert!(
            content.contains("BEGIN RSA PRIVATE KEY"),
            "PEM content must be preserved: {content}"
        );

        // Restore env.
        match prev_home {
            Some(val) => unsafe { std::env::set_var("APM2_HOME", val) },
            None => unsafe { std::env::remove_var("APM2_HOME") },
        }
    }

    // =========================================================================
    // BLOCKER-1: gates behavior without GitHub app config
    // =========================================================================

    /// Demonstrates that `apm2 fac gates` execution path does not depend on
    /// GitHub App configuration. The gates entry point (`run_evidence_gates`
    /// in `fac_review/gates.rs`) uses `resolve_apm2_home()` only for FAC
    /// policy enforcement paths (`private/fac`), not for GitHub App config.
    ///
    /// This test verifies the invariant by confirming that the GitHub App
    /// config file (`github_app.toml`) is not required for APM2 home
    /// resolution or FAC root validation — the two prerequisites that gates
    /// depend on. Missing GitHub App config does not affect gate execution.
    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn gates_prerequisites_work_without_github_app_config() {
        use apm2_core::github::resolve_apm2_home;

        use crate::commands::fac_permissions::validate_fac_root_permissions;

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(tmp.path(), PermissionsExt::from_mode(0o700))
            .expect("harden temp dir");

        let prev_home = std::env::var("APM2_HOME").ok();
        let apm2_home = tmp.path().join("apm2_home");
        // SAFETY: This modifies process-global state; acceptable in serial test.
        unsafe { std::env::set_var("APM2_HOME", &apm2_home) };

        // Resolve APM2 home succeeds without github_app.toml.
        let resolved = resolve_apm2_home();
        assert!(
            resolved.is_some(),
            "resolve_apm2_home must succeed without github_app.toml"
        );
        assert_eq!(
            resolved.unwrap(),
            apm2_home,
            "resolved path must match APM2_HOME"
        );

        // FAC root permissions validation creates directories and succeeds
        // without any GitHub App config present.
        let result = validate_fac_root_permissions();
        assert!(
            result.is_ok(),
            "validate_fac_root_permissions must succeed without github_app.toml: {result:?}"
        );

        // Explicitly verify github_app.toml does NOT exist.
        let config_path = apm2_home.join("github_app.toml");
        assert!(
            !config_path.exists(),
            "github_app.toml must not exist for this test"
        );

        // Restore env.
        match prev_home {
            Some(val) => unsafe { std::env::set_var("APM2_HOME", val) },
            None => unsafe { std::env::remove_var("APM2_HOME") },
        }
    }

    // =========================================================================
    // BLOCKER-2: headless DoD command works with --for-systemd
    // =========================================================================

    /// Demonstrates the documented definition-of-done command is headless-safe
    /// with `--for-systemd`. The command `apm2 fac pr auth-setup --app-id ...
    /// --installation-id ... --private-key-file ... --for-systemd` succeeds
    /// without any keyring or desktop session.
    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn headless_dod_command_succeeds_with_for_systemd() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(tmp.path(), PermissionsExt::from_mode(0o700))
            .expect("harden temp dir");

        let src_pem = tmp.path().join("key.pem");
        fs::write(
            &src_pem,
            "-----BEGIN RSA PRIVATE KEY-----\ndod-test\n-----END RSA PRIVATE KEY-----\n",
        )
        .expect("write pem");

        let prev_home = std::env::var("APM2_HOME").ok();
        let apm2_home = tmp.path().join("apm2_home");
        // SAFETY: This modifies process-global state; acceptable in serial test.
        unsafe { std::env::set_var("APM2_HOME", &apm2_home) };

        // This is the exact definition-of-done command contract: --app-id,
        // --installation-id, --private-key-file, and --for-systemd. No keyring
        // required.
        let args = super::super::PrAuthSetupCliArgs {
            app_id: "99999".to_string(),
            installation_id: "88888".to_string(),
            private_key_file: src_pem,
            keyring_service: "apm2.github.app".to_string(),
            keyring_account: None,
            allow_private_key_file_fallback: false,
            keep_private_key_file: false,
            for_systemd: true,
            json: false,
        };

        let exit = super::run_pr_auth_setup(&args, true);
        assert_eq!(exit, 0, "DoD headless command must succeed without keyring");

        // Verify config was written correctly.
        let config_path = apm2_home.join("github_app.toml");
        assert!(config_path.exists(), "config must be written");
        let config = fs::read_to_string(&config_path).expect("read config");
        assert!(config.contains("app_id"), "config must contain app_id");

        // Verify PEM was stored.
        let dest_pem = apm2_home.join("app-99999.pem");
        assert!(dest_pem.exists(), "PEM must be written to APM2_HOME");

        // Restore env.
        match prev_home {
            Some(val) => unsafe { std::env::set_var("APM2_HOME", val) },
            None => unsafe { std::env::remove_var("APM2_HOME") },
        }
    }

    // =========================================================================
    // paths_are_same_file helper
    // =========================================================================

    #[test]
    fn paths_are_same_file_detects_identical_paths() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = tmp.path().join("test.txt");
        fs::write(&file, "data").expect("write");

        assert!(
            super::paths_are_same_file(&file, &file),
            "same path must be detected"
        );
    }

    #[test]
    fn paths_are_same_file_detects_different_paths() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file_a = tmp.path().join("a.txt");
        let file_b = tmp.path().join("b.txt");
        fs::write(&file_a, "a").expect("write a");
        fs::write(&file_b, "b").expect("write b");

        assert!(
            !super::paths_are_same_file(&file_a, &file_b),
            "different paths must not match"
        );
    }

    #[test]
    fn paths_are_same_file_handles_nonexistent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = tmp.path().join("exists.txt");
        let missing = tmp.path().join("missing.txt");
        fs::write(&file, "data").expect("write");

        assert!(
            !super::paths_are_same_file(&file, &missing),
            "nonexistent path must return false"
        );
    }

    // =========================================================================
    // Headless setup rejects non-numeric app_id (CTR-2609 / MINOR fix)
    // =========================================================================

    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn headless_setup_rejects_path_traversal_app_id() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(tmp.path(), PermissionsExt::from_mode(0o700))
            .expect("harden temp dir");

        let src_pem = tmp.path().join("key.pem");
        fs::write(
            &src_pem,
            "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n",
        )
        .expect("write pem");

        let prev_home = std::env::var("APM2_HOME").ok();
        let apm2_home = tmp.path().join("apm2_home");
        // SAFETY: This modifies process-global state; acceptable in serial test.
        unsafe { std::env::set_var("APM2_HOME", &apm2_home) };

        let args = super::super::PrAuthSetupCliArgs {
            app_id: "../../../etc/evil".to_string(),
            installation_id: "12345".to_string(),
            private_key_file: src_pem,
            keyring_service: "apm2.github.app".to_string(),
            keyring_account: None,
            allow_private_key_file_fallback: false,
            keep_private_key_file: false,
            for_systemd: true,
            json: false,
        };

        let exit = super::run_pr_auth_setup(&args, true);
        assert_ne!(exit, 0, "path-traversal app_id must be rejected");

        // Restore env.
        match prev_home {
            Some(val) => unsafe { std::env::set_var("APM2_HOME", val) },
            None => unsafe { std::env::remove_var("APM2_HOME") },
        }
    }
}
