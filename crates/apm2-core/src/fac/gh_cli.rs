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
//! - [INV-GHCLI-005] `GH_CONFIG_DIR` is always set (to lane-scoped path or
//!   `/dev/null`) to prevent `gh` from reading `~/.config/gh` ambient state.
//! - [INV-GHCLI-006] The returned [`GhCommand`] wrapper redacts `GH_TOKEN` in
//!   its [`Debug`] implementation (CTR-2604), preventing secret leakage via
//!   tracing or debug formatting.

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

impl fmt::Debug for GhCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render the inner Command's debug representation, then redact GH_TOKEN.
        // std::process::Command's Debug output includes env vars as key=value
        // pairs with quoted values (e.g., "GH_TOKEN"="ghp_...").
        let raw = format!("{:?}", self.inner);
        // Redact the GH_TOKEN value. The Debug format for Command renders env
        // vars as "KEY"="VALUE" pairs. We replace the value portion for
        // GH_TOKEN with [REDACTED].
        let redacted = redact_env_value_in_debug(&raw, "GH_TOKEN");
        f.write_str(&redacted)
    }
}

/// Redact the value of a specific environment variable key in the Debug
/// representation of a `std::process::Command`.
///
/// The Debug format renders env vars as `"KEY"="VALUE"`. This function
/// finds `"<key>"="` and replaces everything up to the closing `"` with
/// `"<key>"="[REDACTED]"`.
fn redact_env_value_in_debug(debug_str: &str, key: &str) -> String {
    let needle = format!("\"{key}\"=\"");
    let Some(start) = debug_str.find(&needle) else {
        return debug_str.to_string();
    };
    let value_start = start + needle.len();
    // Find the closing quote of the value, handling possible escaped quotes.
    let rest = &debug_str[value_start..];
    let mut end_offset = 0;
    let mut chars = rest.chars();
    loop {
        match chars.next() {
            Some('\\') => {
                // Skip escaped character.
                if chars.next().is_some() {
                    end_offset += 2;
                } else {
                    end_offset += 1;
                    break;
                }
            },
            Some('"') | None => break,
            Some(c) => end_offset += c.len_utf8(),
        }
    }
    let mut result = String::with_capacity(debug_str.len());
    result.push_str(&debug_str[..value_start]);
    result.push_str("[REDACTED]");
    result.push_str(&debug_str[value_start + end_offset..]);
    result
}

/// Build a `gh` CLI [`GhCommand`] with non-interactive, token-based auth and
/// lane-scoped config directory.
///
/// The returned [`GhCommand`] has:
/// - `GH_TOKEN` set from the credential resolution chain when available, or set
///   to empty string when no token is resolved (fail-closed: prevents
///   inheritance of ambient `GH_TOKEN` from parent process).
/// - `GH_CONFIG_DIR` set to `$XDG_CONFIG_HOME/gh` when `XDG_CONFIG_HOME` is
///   available (lane-scoped), or `/dev/null` otherwise (fail-closed: prevents
///   reads from `~/.config/gh`).
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
/// `GH_TOKEN` is set to empty string and `GH_CONFIG_DIR` is set to `/dev/null`,
/// preventing inheritance of ambient authority from the parent process or
/// `~/.config/gh` state. Callers that require auth should gate on
/// [`crate::fac::require_github_credentials`] before invoking `gh`.
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
    // When XDG_CONFIG_HOME is set (per-lane env from TCK-00575), use it as
    // the base for gh config. Otherwise set GH_CONFIG_DIR to /dev/null to
    // prevent gh from reading the user-global ~/.config/gh directory.
    let gh_config_dir = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map_or_else(
            || std::path::PathBuf::from("/dev/null"),
            |xdg| std::path::PathBuf::from(&xdg).join("gh"),
        );
    cmd.env("GH_CONFIG_DIR", gh_config_dir);

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
    fn redact_env_value_in_debug_handles_missing_key() {
        let input = r#""gh" "GH_NO_UPDATE_NOTIFIER"="1""#;
        let result = redact_env_value_in_debug(input, "GH_TOKEN");
        assert_eq!(result, input, "No GH_TOKEN key means no change");
    }

    #[test]
    fn redact_env_value_in_debug_replaces_value() {
        let input = r#""gh" "GH_TOKEN"="secret123" "OTHER"="val""#;
        let result = redact_env_value_in_debug(input, "GH_TOKEN");
        assert_eq!(result, r#""gh" "GH_TOKEN"="[REDACTED]" "OTHER"="val""#);
    }

    #[test]
    fn redact_env_value_in_debug_handles_empty_value() {
        let input = r#""gh" "GH_TOKEN"="" "OTHER"="val""#;
        let result = redact_env_value_in_debug(input, "GH_TOKEN");
        assert_eq!(result, r#""gh" "GH_TOKEN"="[REDACTED]" "OTHER"="val""#);
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
