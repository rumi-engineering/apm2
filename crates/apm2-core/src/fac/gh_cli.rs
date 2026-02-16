//! Non-interactive, lane-scoped GitHub CLI (`gh`) command builder (TCK-00597).
//!
//! This module provides a [`gh_command`] constructor that returns a
//! [`std::process::Command`] pre-configured for token-based, non-interactive
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

use std::process::Command;

use secrecy::ExposeSecret;

/// Build a `gh` CLI [`Command`] with non-interactive, token-based auth and
/// lane-scoped config directory.
///
/// The returned [`Command`] has:
/// - `GH_TOKEN` set from the credential resolution chain (env var, systemd
///   credential, APM2 credential file) when available.
/// - `GH_CONFIG_DIR` set to `$XDG_CONFIG_HOME/gh` when `XDG_CONFIG_HOME` is
///   available (lane-scoped), preventing writes to `~/.config/gh`.
/// - `GH_NO_UPDATE_NOTIFIER=1` to suppress interactive update checks.
/// - `NO_COLOR=1` to suppress ANSI color codes in output for reliable parsing.
/// - `GH_PROMPT_DISABLED=1` to prevent any interactive prompts.
///
/// Callers add their own arguments (`api`, `pr`, etc.) after calling this
/// function.
///
/// # Fail-Open Note
///
/// If no token is available, the command is still returned (without
/// `GH_TOKEN`). This allows `gh` to fall back to any ambient auth state
/// (`gh auth login` or a pre-existing `GH_TOKEN` in the environment).
/// Callers that require auth should gate on
/// [`crate::fac::require_github_credentials`] before invoking `gh`.
#[must_use]
pub fn gh_command() -> Command {
    let mut cmd = Command::new("gh");

    // INV-GHCLI-003: Suppress interactive update notifier.
    cmd.env("GH_NO_UPDATE_NOTIFIER", "1");

    // Suppress color codes for deterministic output parsing.
    cmd.env("NO_COLOR", "1");

    // Prevent any interactive prompts from the gh CLI.
    cmd.env("GH_PROMPT_DISABLED", "1");

    // Inject GH_TOKEN from the credential resolution chain (INV-GHCLI-001).
    // Resolution order: GITHUB_TOKEN env → GH_TOKEN env → systemd credential
    // → APM2 credential file.
    if let Some(token) = crate::config::resolve_github_token("GITHUB_TOKEN")
        .or_else(|| crate::config::resolve_github_token("GH_TOKEN"))
    {
        cmd.env("GH_TOKEN", token.expose_secret());
    }

    // Lane-scope the gh config directory (INV-GHCLI-002).
    // When XDG_CONFIG_HOME is set (per-lane env from TCK-00575), use it as
    // the base for gh config. This prevents gh from writing into the
    // user-global ~/.config/gh directory.
    if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg_config.is_empty() {
            let gh_config = std::path::Path::new(&xdg_config).join("gh");
            cmd.env("GH_CONFIG_DIR", gh_config);
        }
    }

    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gh_command_sets_non_interactive_env_vars() {
        let cmd = gh_command();
        let envs: std::collections::HashMap<_, _> = cmd
            .get_envs()
            .filter_map(|(key, value)| Some((key.to_str()?, value?.to_str()?)))
            .collect();

        assert_eq!(envs.get("GH_NO_UPDATE_NOTIFIER"), Some(&"1"));
        assert_eq!(envs.get("NO_COLOR"), Some(&"1"));
        assert_eq!(envs.get("GH_PROMPT_DISABLED"), Some(&"1"));
    }

    #[test]
    fn gh_command_program_is_gh() {
        let cmd = gh_command();
        assert_eq!(cmd.get_program(), "gh");
    }

    #[test]
    fn gh_command_does_not_set_synthetic_token() {
        // When no token is available in the environment, GH_TOKEN should
        // not be set to any synthetic placeholder.
        //
        // Note: In CI or dev environments where GITHUB_TOKEN/GH_TOKEN is
        // actually set, this test still passes because the resolved value
        // is the real token (not a placeholder). The invariant is that we
        // never inject a fake value.
        let cmd = gh_command();
        let envs: std::collections::HashMap<_, _> = cmd
            .get_envs()
            .filter_map(|(key, value)| Some((key.to_str()?, value?.to_str()?)))
            .collect();

        if let Some(token) = envs.get("GH_TOKEN") {
            // If GH_TOKEN is set, it must be a non-empty, non-placeholder value
            assert!(!token.is_empty(), "GH_TOKEN must not be empty");
            assert!(
                *token != "PLACEHOLDER",
                "GH_TOKEN must not be a synthetic placeholder"
            );
        }
    }
}
