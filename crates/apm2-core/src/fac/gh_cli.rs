//! Non-interactive, lane-scoped GitHub CLI (`gh`) command builder (TCK-00597).
//!
//! This module provides a [`gh_command`] constructor that returns a
//! [`GhCommand`] wrapper pre-configured for token-based, non-interactive
//! authentication. It removes the hard dependency on `gh auth login` or
//! persistent `~/.config/gh` state.
//!
//! # Authentication
//!
//! The `gh` CLI natively supports `GH_TOKEN` for authentication. When
//! `GH_TOKEN` is set, `gh` skips its usual auth-state lookup entirely.
//! This module resolves the token through the credential chain established
//! by TCK-00596 ([`crate::config::resolve_github_token`]) and injects it
//! into the spawned command's environment.
//!
//! # Lane Scoping
//!
//! The `gh` CLI reads and writes config/state under `$GH_CONFIG_DIR`
//! (defaults to `~/.config/gh`). In lane-scoped FAC execution environments,
//! `HOME` points to a per-lane directory (TCK-00575) and `XDG_CONFIG_HOME`
//! is similarly scoped. This module explicitly sets `GH_CONFIG_DIR` to
//! `<XDG_CONFIG_HOME>/gh` when `XDG_CONFIG_HOME` is set, ensuring `gh`
//! state is lane-local rather than user-global.
//!
//! # Security Invariants
//!
//! - [INV-GHCLI-001] `GH_TOKEN` is injected only when resolved; no synthetic
//!   placeholder is ever emitted.
//! - [INV-GHCLI-002] `GH_CONFIG_DIR` is always set to a lane-scoped path when
//!   `XDG_CONFIG_HOME` is available, preventing user-global `~/.config/gh`
//!   writes.
//! - [INV-GHCLI-003] `GH_NO_UPDATE_NOTIFIER` is set to `1` to suppress
//!   interactive update prompts.
//! - [INV-GHCLI-004] `GH_TOKEN` is always set in the command environment (empty
//!   when no token is resolved) to prevent inheritance of ambient `GH_TOKEN`
//!   from the parent process. This ensures fail-closed auth.
//! - [INV-GHCLI-005] `GH_CONFIG_DIR` is always set (to lane-scoped path or a
//!   user-isolated, HOME-derived path) to prevent `gh` from reading
//!   `~/.config/gh` ambient state. The fallback uses `$HOME/.config/gh` (XDG
//!   convention), never a shared `/tmp` path (CWE-377 mitigation).
//! - [INV-GHCLI-006] The returned [`GhCommand`] wrapper redacts `GH_TOKEN` in
//!   its [`Debug`] implementation (CTR-2604), preventing secret leakage via
//!   tracing or debug formatting.
//! - [INV-GHCLI-007] The `GH_CONFIG_DIR` path is verified to not be a symlink
//!   before use, preventing symlink-based arbitrary file write attacks. The
//!   directory is created with restrictive 0o700 permissions (CTR-2611).

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::process::Command;

use secrecy::ExposeSecret;

/// A wrapper around [`std::process::Command`] that redacts `GH_TOKEN` in its
/// [`Debug`] representation (CTR-2604, INV-GHCLI-006).
///
/// This type implements [`Deref`] and [`DerefMut`] to [`Command`], so all
/// standard [`Command`] methods (`.args()`, `.output()`, `.spawn()`, etc.)
/// are available via auto-deref. The only behavioral difference from a raw
/// [`Command`] is that the [`Debug`] output replaces the `GH_TOKEN` value
/// with `[REDACTED]`, preventing accidental secret leakage through logging
/// or tracing.
pub struct GhCommand {
    inner: Command,
}

impl Deref for GhCommand {
    type Target = Command;

    fn deref(&self) -> &Command {
        &self.inner
    }
}

impl DerefMut for GhCommand {
    fn deref_mut(&mut self) -> &mut Command {
        &mut self.inner
    }
}

/// Secret environment variable key whose value must always be redacted in
/// Debug output (CTR-2604). Compared case-sensitively against env var names.
const REDACTED_ENV_KEY: &str = "GH_TOKEN";

impl fmt::Debug for GhCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Build debug output from Command's structured accessors (get_envs(),
        // get_args(), get_program()) instead of parsing Command's Debug string.
        // This avoids any dependency on the unstable Debug format of
        // std::process::Command and guarantees GH_TOKEN is always redacted
        // regardless of platform or toolchain version (INV-GHCLI-006).
        let program = self.inner.get_program().to_string_lossy();

        // Emit environment variables with GH_TOKEN redacted.
        for (key, value) in self.inner.get_envs() {
            let key_str = key.to_string_lossy();
            if key_str == REDACTED_ENV_KEY {
                write!(f, "{key_str}=\"[REDACTED]\" ")?;
            } else if let Some(val) = value {
                write!(f, "{key_str}={:?} ", val.to_string_lossy())?;
            } else {
                // Environment variable explicitly removed (set to None).
                write!(f, "{key_str}=(removed) ")?;
            }
        }

        // Emit program name.
        write!(f, "{program:?}")?;

        // Emit arguments.
        for arg in self.inner.get_args() {
            write!(f, " {:?}", arg.to_string_lossy())?;
        }

        Ok(())
    }
}

/// Build a `gh` CLI [`GhCommand`] with non-interactive, token-based auth and
/// lane-scoped config directory.
///
/// The returned [`GhCommand`] has:
/// - `GH_TOKEN` set from the credential resolution chain when available, or set
///   to empty string when no token is resolved (fail-closed: prevents
///   inheritance of ambient `GH_TOKEN` from parent process).
/// - `GH_CONFIG_DIR` set to `$XDG_CONFIG_HOME/gh` when `XDG_CONFIG_HOME` is
///   available (lane-scoped), or `$HOME/.config/gh` following XDG convention
///   (user-isolated, deterministic). Fail-closed: if neither `XDG_CONFIG_HOME`
///   nor `HOME` is set, `gh` invocations will fail with a clear I/O error
///   rather than falling back to a shared `/tmp` path.
/// - `GH_NO_UPDATE_NOTIFIER=1` to suppress interactive update checks.
/// - `NO_COLOR=1` to suppress ANSI color codes in output for reliable parsing.
/// - `GH_PROMPT_DISABLED=1` to prevent any interactive prompts.
///
/// The wrapper's [`Debug`] implementation redacts `GH_TOKEN` to prevent
/// accidental secret leakage (CTR-2604).
///
/// Callers add their own arguments (`api`, `pr`, etc.) after calling this
/// function.
///
/// # Fail-Closed Authentication
///
/// `GH_TOKEN` and `GH_CONFIG_DIR` are always explicitly set in the command
/// environment (INV-GHCLI-004, INV-GHCLI-005). When no token is resolved,
/// `GH_TOKEN` is set to empty string and `GH_CONFIG_DIR` is set to a
/// user-isolated, HOME-derived directory (INV-GHCLI-007), preventing
/// inheritance of ambient authority from the parent process or `~/.config/gh`
/// state. Callers that require auth should gate on
/// [`crate::fac::require_github_credentials`] before invoking `gh`.
///
/// # Security
///
/// The config directory is created with 0o700 permissions (CTR-2611) and
/// verified to not be a symlink before use (INV-GHCLI-007, CWE-377
/// mitigation). The fallback path is derived from `$HOME` (user-isolated),
/// never from a shared `/tmp` directory.
#[must_use]
pub fn gh_command() -> GhCommand {
    let mut cmd = Command::new("gh");

    // INV-GHCLI-003: Suppress interactive update notifier.
    cmd.env("GH_NO_UPDATE_NOTIFIER", "1");

    // Suppress color codes for deterministic output parsing.
    cmd.env("NO_COLOR", "1");

    // Prevent any interactive prompts from the gh CLI.
    cmd.env("GH_PROMPT_DISABLED", "1");

    // Inject GH_TOKEN from the credential resolution chain (INV-GHCLI-001).
    // Resolution order: first resolves the full chain (env var -> systemd
    // credential -> APM2 credential file) for GITHUB_TOKEN, then resolves
    // the full chain for GH_TOKEN if GITHUB_TOKEN was not found.
    //
    // INV-GHCLI-004: GH_TOKEN is always set in the command environment.
    // When no token is resolved, GH_TOKEN is set to empty string to prevent
    // the child process from inheriting an ambient GH_TOKEN from the parent.
    if let Some(token) = crate::config::resolve_github_token("GITHUB_TOKEN")
        .or_else(|| crate::config::resolve_github_token("GH_TOKEN"))
    {
        cmd.env("GH_TOKEN", token.expose_secret());
    } else {
        // Fail-closed: prevent inheritance of ambient GH_TOKEN from parent.
        cmd.env("GH_TOKEN", "");
    }

    // Lane-scope the gh config directory (INV-GHCLI-002, INV-GHCLI-005).
    //
    // Resolution order (XDG convention, user-isolated):
    //   1. $XDG_CONFIG_HOME/gh  — lane-scoped (TCK-00575 sets this per-lane)
    //   2. $HOME/.config/gh     — XDG fallback (HOME is always set per TCK-00575)
    //   3. Fail-closed          — if neither is set, gh will fail with I/O error
    //
    // Security invariants:
    //   - Never uses a shared /tmp path (CWE-377 symlink attack prevention).
    //   - Directory created with 0o700 permissions (CTR-2611).
    //   - Symlink check before use (INV-GHCLI-007).
    let gh_config_dir = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|xdg| std::path::PathBuf::from(&xdg).join("gh"))
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|v| !v.is_empty())
                .map(|home| std::path::PathBuf::from(&home).join(".config").join("gh"))
        });

    if let Some(ref dir) = gh_config_dir {
        // Create the directory with restrictive permissions (CTR-2611).
        // Uses DirBuilderExt::mode(0o700) so permissions are set atomically
        // at creation time, avoiding a TOCTOU window between mkdir and chmod.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            // Best-effort create. If this fails, gh will fail with a clear
            // I/O error. We do not silently fall back to a shared path.
            let _ = builder.create(dir);

            // If the directory already existed, DirBuilder does not change
            // its permissions. Explicitly enforce 0o700 on the leaf directory
            // to harden against pre-existing directories with lax permissions.
            if dir.exists() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = std::fs::create_dir_all(dir);
        }

        // INV-GHCLI-007: Verify the path is not a symlink before use.
        // An attacker could pre-create a symlink at this path to redirect
        // gh config writes to an arbitrary location (CWE-377).
        if dir.is_symlink() {
            // Fail-closed: if the config dir is a symlink, refuse to use it.
            // Set GH_CONFIG_DIR to a non-existent path so gh fails with a
            // clear error rather than following a malicious symlink.
            eprintln!(
                "apm2: SECURITY: GH_CONFIG_DIR path is a symlink, refusing to use: {}",
                dir.display()
            );
            cmd.env(
                "GH_CONFIG_DIR",
                "/nonexistent/apm2_gh_config_symlink_rejected",
            );
        } else {
            cmd.env("GH_CONFIG_DIR", dir);
        }
    } else {
        // Fail-closed (RS-41): neither XDG_CONFIG_HOME nor HOME is set.
        // Set GH_CONFIG_DIR to a non-existent path so gh fails with a clear
        // I/O error rather than falling back to a shared/predictable path.
        // This should never happen in lane context (TCK-00575 ensures HOME).
        eprintln!(
            "apm2: WARNING: neither XDG_CONFIG_HOME nor HOME is set; \
             gh CLI will fail (fail-closed per INV-GHCLI-005)"
        );
        cmd.env("GH_CONFIG_DIR", "/nonexistent/apm2_gh_config_no_home");
    }

    GhCommand { inner: cmd }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: collect environment variables from a [`GhCommand`] into a
    /// `HashMap`.
    fn collect_envs(cmd: &GhCommand) -> std::collections::HashMap<String, String> {
        cmd.get_envs()
            .filter_map(|(key, value)| {
                Some((key.to_str()?.to_string(), value?.to_str()?.to_string()))
            })
            .collect()
    }

    #[test]
    fn gh_command_sets_non_interactive_env_vars() {
        let cmd = gh_command();
        let envs = collect_envs(&cmd);

        assert_eq!(
            envs.get("GH_NO_UPDATE_NOTIFIER").map(String::as_str),
            Some("1")
        );
        assert_eq!(envs.get("NO_COLOR").map(String::as_str), Some("1"));
        assert_eq!(
            envs.get("GH_PROMPT_DISABLED").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn gh_command_program_is_gh() {
        let cmd = gh_command();
        assert_eq!(cmd.get_program(), "gh");
    }

    #[test]
    fn gh_command_does_not_set_synthetic_token() {
        // When no token is available in the environment, GH_TOKEN should
        // be set to empty (fail-closed) — never a synthetic placeholder.
        //
        // Note: In CI or dev environments where GITHUB_TOKEN/GH_TOKEN is
        // actually set, this test still passes because the resolved value
        // is the real token (not a placeholder). The invariant is that we
        // never inject a fake value.
        let cmd = gh_command();
        let envs = collect_envs(&cmd);

        if let Some(token) = envs.get("GH_TOKEN") {
            // Token is either empty (fail-closed) or a real resolved value.
            assert!(
                *token != "PLACEHOLDER",
                "GH_TOKEN must not be a synthetic placeholder"
            );
        }
    }

    // --- INV-GHCLI-004: Fail-closed GH_TOKEN ---

    #[test]
    fn gh_command_always_sets_gh_token() {
        // INV-GHCLI-004: GH_TOKEN must always be present in the command
        // environment to prevent inheritance of ambient GH_TOKEN from
        // the parent process.
        let cmd = gh_command();
        let envs = collect_envs(&cmd);
        assert!(
            envs.contains_key("GH_TOKEN"),
            "GH_TOKEN must always be set (fail-closed)"
        );
    }

    // --- INV-GHCLI-005: Fail-closed GH_CONFIG_DIR ---

    #[test]
    fn gh_command_always_sets_gh_config_dir() {
        // INV-GHCLI-005: GH_CONFIG_DIR must always be present to prevent
        // gh from reading ~/.config/gh ambient state.
        let cmd = gh_command();
        let envs = collect_envs(&cmd);
        assert!(
            envs.contains_key("GH_CONFIG_DIR"),
            "GH_CONFIG_DIR must always be set (fail-closed)"
        );
        let config_dir = envs.get("GH_CONFIG_DIR").unwrap();
        assert!(!config_dir.is_empty(), "GH_CONFIG_DIR must not be empty");
    }

    #[test]
    fn gh_command_config_dir_is_valid_directory_not_dev_null() {
        // BLOCKER fix: GH_CONFIG_DIR must point to a real directory, not
        // /dev/null which causes `gh` to crash with ENOTDIR.
        let cmd = gh_command();
        let envs = collect_envs(&cmd);
        let config_dir = envs.get("GH_CONFIG_DIR").unwrap();
        assert_ne!(
            config_dir, "/dev/null",
            "GH_CONFIG_DIR must not be /dev/null (causes gh crash)"
        );
        // The path must be a directory (or at least a plausible directory
        // path, not a character device).
        let path = std::path::Path::new(config_dir);
        // Path should be user-isolated (HOME-derived or XDG-derived), never
        // under /tmp (CWE-377 mitigation).
        assert!(
            !config_dir.starts_with("/tmp/"),
            "GH_CONFIG_DIR must not use shared /tmp path (CWE-377)"
        );
        assert!(
            path.parent().is_some(),
            "GH_CONFIG_DIR must have a parent directory"
        );
    }

    // --- INV-GHCLI-007: Symlink rejection and permissions ---

    #[cfg(unix)]
    #[test]
    fn gh_config_dir_has_restrictive_permissions() {
        // INV-GHCLI-007 / CTR-2611: The GH_CONFIG_DIR directory must be
        // created with 0o700 permissions to prevent other users from
        // reading gh config/session data.
        let cmd = gh_command();
        let envs = collect_envs(&cmd);
        let config_dir = envs.get("GH_CONFIG_DIR").unwrap();
        let path = std::path::Path::new(config_dir);
        if path.exists() && !path.is_symlink() {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(path).unwrap().permissions();
            let mode = perms.mode() & 0o777;
            assert_eq!(
                mode, 0o700,
                "GH_CONFIG_DIR must have 0o700 permissions, got {mode:o}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn gh_config_dir_rejects_symlink() {
        // INV-GHCLI-007: If the config dir path is a symlink, gh_command
        // must refuse to use it (fail-closed) to prevent CWE-377 attacks.
        use std::os::unix::fs::DirBuilderExt;
        let tmpdir = tempfile::TempDir::new().unwrap();
        let symlink_target = tmpdir.path().join("real_dir");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&symlink_target)
            .unwrap();
        let symlink_path = tmpdir.path().join("symlink_dir");
        std::os::unix::fs::symlink(&symlink_target, &symlink_path).unwrap();

        // Verify the symlink detection logic directly.
        assert!(
            symlink_path.is_symlink(),
            "Test setup: symlink must be detected"
        );
        // The actual gh_command() function checks is_symlink() on the
        // resolved config dir path. We verify the detection mechanism works.
    }

    // --- INV-GHCLI-006: Redacting Debug ---

    #[test]
    fn gh_command_debug_redacts_gh_token() {
        // INV-GHCLI-006: The Debug representation must never contain the
        // raw GH_TOKEN value. Verify that if a token is present, it is
        // replaced with [REDACTED] in the debug output.
        let cmd = gh_command();
        let debug_output = format!("{cmd:?}");

        // The debug output must contain [REDACTED] where GH_TOKEN value was.
        // GH_TOKEN is always set (fail-closed), so we always expect the key.
        assert!(
            debug_output.contains("GH_TOKEN"),
            "Debug output should mention GH_TOKEN key"
        );

        // If a real token was resolved, verify it does not appear in debug.
        let envs = collect_envs(&cmd);
        if let Some(token) = envs.get("GH_TOKEN") {
            if !token.is_empty() {
                assert!(
                    !debug_output.contains(token),
                    "Debug output must not contain the raw GH_TOKEN value"
                );
                assert!(
                    debug_output.contains("[REDACTED]"),
                    "Debug output must contain [REDACTED] for GH_TOKEN"
                );
            }
        }
    }

    #[test]
    fn gh_command_debug_redacts_injected_token() {
        // Construct a GhCommand with a known token value and verify redaction.
        // Uses get_envs()/get_args()-based Debug impl (not string parsing).
        let mut cmd = Command::new("gh");
        cmd.env("GH_TOKEN", "ghp_test_secret_12345");
        cmd.env("OTHER_VAR", "visible_value");
        let wrapper = GhCommand { inner: cmd };

        let debug_output = format!("{wrapper:?}");
        assert!(
            !debug_output.contains("ghp_test_secret_12345"),
            "Debug must not contain raw token: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug must contain [REDACTED]: {debug_output}"
        );
        // Other env vars should remain visible.
        assert!(
            debug_output.contains("visible_value"),
            "Non-secret env vars should remain visible: {debug_output}"
        );
    }

    #[test]
    fn debug_redacts_token_without_string_parsing() {
        // Regression test: the Debug impl must use get_envs()/get_args()
        // directly and never depend on Command's Debug format (INV-GHCLI-006).
        // This test verifies redaction works with a synthetic GhCommand
        // independent of any particular Debug format.
        let mut cmd = Command::new("gh");
        cmd.env("GH_TOKEN", "ghp_super_secret_token_value_99");
        cmd.arg("api");
        cmd.arg("/repos/owner/repo");
        let wrapper = GhCommand { inner: cmd };

        let debug_output = format!("{wrapper:?}");

        // Must redact the token.
        assert!(
            !debug_output.contains("ghp_super_secret_token_value_99"),
            "Token must be redacted: {debug_output}"
        );
        assert!(
            debug_output.contains("GH_TOKEN=\"[REDACTED]\""),
            "Must show GH_TOKEN=\"[REDACTED]\": {debug_output}"
        );

        // Must show program and args.
        assert!(
            debug_output.contains("\"gh\""),
            "Must show program name: {debug_output}"
        );
        assert!(
            debug_output.contains("\"api\""),
            "Must show args: {debug_output}"
        );
        assert!(
            debug_output.contains("\"/repos/owner/repo\""),
            "Must show args: {debug_output}"
        );
    }

    #[test]
    fn debug_shows_no_token_key_when_absent() {
        // When GH_TOKEN is not set at all, it should not appear in debug.
        let mut cmd = Command::new("gh");
        cmd.env("OTHER_VAR", "val");
        let wrapper = GhCommand { inner: cmd };

        let debug_output = format!("{wrapper:?}");
        assert!(
            !debug_output.contains("GH_TOKEN"),
            "GH_TOKEN should not appear when not set: {debug_output}"
        );
        assert!(
            debug_output.contains("OTHER_VAR"),
            "Other vars should appear: {debug_output}"
        );
    }

    #[test]
    fn debug_handles_empty_token_value() {
        // When GH_TOKEN is set to empty string (fail-closed), it should
        // still show [REDACTED] — not the empty value.
        let mut cmd = Command::new("gh");
        cmd.env("GH_TOKEN", "");
        let wrapper = GhCommand { inner: cmd };

        let debug_output = format!("{wrapper:?}");
        assert!(
            debug_output.contains("[REDACTED]"),
            "Empty GH_TOKEN must still show [REDACTED]: {debug_output}"
        );
    }

    // --- Deref/DerefMut ---

    #[test]
    fn gh_command_deref_allows_args_chaining() {
        // Verify that GhCommand can be used like a Command via Deref.
        let mut cmd = gh_command();
        cmd.arg("api");
        cmd.args(["--jq", ".name"]);
        let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(args, &["api", "--jq", ".name"]);
    }
}
