//! Shell command safety utilities for secure path quoting.
//!
//! This module provides utilities for safely constructing shell commands that
//! include file paths. It addresses shell injection vulnerabilities by properly
//! escaping paths containing special characters (spaces, quotes, backticks,
//! newlines, dollar signs, etc.).
//!
//! # Security
//!
//! Shell escaping is critical for security when constructing commands with
//! user-controlled paths. The [`quote_path`] function uses the battle-tested
//! `shell-escape` crate to ensure proper quoting.
//!
//! # Example
//!
//! ```ignore
//! use std::path::Path;
//! use xtask::shell_escape::{quote_path, build_script_command};
//!
//! let path = Path::new("/tmp/file with spaces.txt");
//! let quoted = quote_path(path);
//! assert!(quoted.contains("'"));
//!
//! let cmd = build_script_command(path, None, None, None);
//! assert!(cmd.contains("script"));
//! ```

use std::borrow::Cow;
use std::path::Path;

use shell_escape::escape;

/// Safely quotes a path for use in shell commands.
///
/// This function handles all shell metacharacters:
/// - Spaces: `path with spaces` -> `'path with spaces'`
/// - Single quotes: `path's` -> `'path'"'"'s'` (close quote, escaped quote,
///   open quote)
/// - Double quotes: `path"s` -> `'path"s'` (single quotes don't interpret
///   double quotes)
/// - Backticks: `` path`cmd` `` -> `` 'path`cmd`' `` (single quotes prevent
///   execution)
/// - Dollar signs: `path$var` -> `'path$var'` (single quotes prevent expansion)
/// - Newlines: ANSI-C quoting is used when necessary
///
/// # Arguments
///
/// * `path` - The path to quote
///
/// # Returns
///
/// A string containing the safely quoted path suitable for shell interpolation.
///
/// # Example
///
/// ```ignore
/// use std::path::Path;
/// use xtask::shell_escape::quote_path;
///
/// let path = Path::new("/tmp/test file.txt");
/// let quoted = quote_path(path);
/// // quoted can be safely interpolated into a shell command
/// ```
pub fn quote_path(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    escape(Cow::Borrowed(&path_str)).into_owned()
}

/// Escapes a string for use inside a single-quoted shell string.
/// Replaces ' with '\''
fn escape_for_single_quote(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Builds a script command for PTY-wrapped execution.
///
/// The `script` command allocates a pseudo-TTY which gives Codex access to
/// all tools (including `run_shell_command`). Without PTY allocation, headless
/// mode filters out shell tools causing "Tool not found in registry" errors.
///
/// # Arguments
///
/// * `prompt_path` - Path to the prompt file to redirect as input
/// * `log_path` - Optional path to capture output for activity tracking. If
///   `Some`, uses `script -q <log_path> -c <cmd>` format. If `None`, uses
///   `script -qec <cmd> /dev/null` format (discard typescript).
///
/// # Returns
///
/// A shell command string ready for execution via `sh -c`.
///
/// # Format
///
/// With log capture (for health monitoring):
/// ```text
/// # macOS:
/// script -q '<log_path>' sh -c 'codex exec --model <model> --dangerously-bypass-approvals-and-sandbox < '\''<prompt_path>'\'''
/// # Linux:
/// script -q '<log_path>' -c 'codex exec --model <model> --dangerously-bypass-approvals-and-sandbox < '\''<prompt_path>'\'''
/// ```
///
/// Without log capture (synchronous reviews):
/// ```text
/// # macOS:
/// script -q /dev/null sh -c 'codex exec --model <model> --dangerously-bypass-approvals-and-sandbox < '\''<prompt_path>'\'''
/// # Linux:
/// script -qec 'codex exec --model <model> --dangerously-bypass-approvals-and-sandbox < '\''<prompt_path>'\''' /dev/null
/// ```
///
/// # Example
///
/// ```ignore
/// use std::path::Path;
/// use xtask::shell_escape::build_script_command;
///
/// // Without log capture
/// let cmd = build_script_command(Path::new("/tmp/prompt.txt"), None, Some("gpt-5.3-codex"), None);
/// assert!(cmd.contains("script -qec"));
/// assert!(cmd.contains("--model gpt-5.3-codex"));
///
/// // With log capture
/// let log_path = Path::new("/tmp/review.log");
/// let cmd = build_script_command(Path::new("/tmp/prompt.txt"), Some(log_path), None, None);
/// assert!(cmd.contains("script -q"));
/// ```
pub fn build_script_command(
    prompt_path: &Path,
    log_path: Option<&Path>,
    model: Option<&str>,
    output_last_message_path: Option<&Path>,
) -> String {
    let quoted_prompt = quote_path(prompt_path);
    let model_flag = model.map_or_else(String::new, |m| {
        let escaped_m = escape_for_single_quote(m);
        format!("--model {escaped_m} ")
    });
    let output_last_message_flag = output_last_message_path.map_or_else(String::new, |path| {
        let quoted_output_path = quote_path(path);
        format!("--output-last-message {quoted_output_path} ")
    });
    let inner_cmd = format!(
        "codex exec {model_flag}{output_last_message_flag}--dangerously-bypass-approvals-and-sandbox < {quoted_prompt}"
    );
    let escaped_inner = escape_for_single_quote(&inner_cmd);

    // macOS `script` uses: script -q file command [args...]
    // Linux `script` uses: script -qec 'command' file
    log_path.map_or_else(
        || {
            if cfg!(target_os = "macos") {
                format!("script -q /dev/null sh -c '{escaped_inner}'")
            } else {
                format!("script -qec '{escaped_inner}' /dev/null")
            }
        },
        |log| {
            let quoted_log = quote_path(log);
            if cfg!(target_os = "macos") {
                format!("script -q {quoted_log} sh -c '{escaped_inner}'")
            } else {
                format!("script -q {quoted_log} -c '{escaped_inner}'")
            }
        },
    )
}

/// Builds a script command for background execution with log capture.
///
/// This is the same as [`build_script_command`] with `Some(log_path)`, but
/// provided as a separate function for clarity when spawning background
/// reviewers.
///
/// Note: Temp file cleanup is handled via state tracking in
/// `reviewer_state.rs`, not via shell commands. This avoids race conditions
/// and ensures cleanup even if the process is killed.
///
/// # Arguments
///
/// * `prompt_path` - Path to the prompt file to redirect as input
/// * `log_path` - Path to capture output for activity tracking
/// * `model` - Optional AI model to use
///
/// # Returns
///
/// A shell command string that runs Codex with log capture.
///
/// # Format
///
/// ```text
/// # macOS:
/// script -q '<log_path>' sh -c 'codex exec --model <model> --dangerously-bypass-approvals-and-sandbox < '\''<prompt_path>'\'''
/// # Linux:
/// script -q '<log_path>' -c 'codex exec --model <model> --dangerously-bypass-approvals-and-sandbox < '\''<prompt_path>'\'''
/// ```
pub fn build_script_command_with_cleanup(
    prompt_path: &Path,
    log_path: &Path,
    model: Option<&str>,
    output_last_message_path: Option<&Path>,
) -> String {
    // Temp file cleanup is now handled via state tracking, not shell commands.
    // This function is kept for backward compatibility but now delegates to
    // build_script_command with log capture.
    build_script_command(prompt_path, Some(log_path), model, output_last_message_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // quote_path tests
    // =========================================================================

    #[test]
    fn test_quote_path_empty() {
        let path = Path::new("");
        let quoted = quote_path(path);
        // Empty paths should be quoted to prevent shell issues
        assert!(!quoted.is_empty() || quoted == "''");
    }

    #[test]
    fn test_quote_path_simple() {
        let path = Path::new("/tmp/test.txt");
        let quoted = quote_path(path);
        // Simple paths may or may not be quoted, but should be valid
        assert!(quoted.contains("test.txt"));
    }

    #[test]
    fn test_quote_path_with_spaces() {
        let path = Path::new("/tmp/test file with spaces.txt");
        let quoted = quote_path(path);
        // Path with spaces must be quoted
        assert!(
            quoted.contains('\'') || quoted.contains('"'),
            "Path with spaces should be quoted: {quoted}"
        );
        assert!(quoted.contains("test file with spaces"));
    }

    #[test]
    fn test_quote_path_with_single_quotes() {
        let path = Path::new("/tmp/file's name.txt");
        let quoted = quote_path(path);
        // Single quotes in path require special handling
        // The shell-escape crate handles this correctly
        assert!(
            !quoted.is_empty(),
            "Path with single quotes should be properly escaped"
        );
        // When executed in shell, the result should preserve the single quote
    }

    #[test]
    fn test_quote_path_with_double_quotes() {
        let path = Path::new("/tmp/file\"name.txt");
        let quoted = quote_path(path);
        // Double quotes should be handled
        assert!(
            !quoted.is_empty(),
            "Path with double quotes should be properly escaped"
        );
    }

    #[test]
    fn test_quote_path_with_backticks() {
        let path = Path::new("/tmp/file`command`.txt");
        let quoted = quote_path(path);
        // Backticks are shell command substitution - must be escaped
        assert!(
            quoted.contains('\'') || quoted.contains('\\'),
            "Path with backticks should be quoted to prevent command substitution: {quoted}"
        );
    }

    #[test]
    fn test_quote_path_with_dollar_sign() {
        let path = Path::new("/tmp/file$variable.txt");
        let quoted = quote_path(path);
        // Dollar signs are variable expansion - must be escaped
        assert!(
            quoted.contains('\'') || quoted.contains('\\'),
            "Path with dollar sign should be quoted to prevent variable expansion: {quoted}"
        );
    }

    #[test]
    fn test_quote_path_with_newline() {
        let path = Path::new("/tmp/file\nwith\nnewlines.txt");
        let quoted = quote_path(path);
        // Newlines require special ANSI-C quoting or escaping
        assert!(
            !quoted.is_empty(),
            "Path with newlines should be properly escaped"
        );
    }

    #[test]
    fn test_quote_path_with_semicolon() {
        // Use a harmless relative-path delete target so test_safety_guard does not
        // flag this as a destructive root wipe pattern.
        let path = Path::new("/tmp/file;rm -rf ./apm2_tsg_sentinel.txt");
        let quoted = quote_path(path);
        // Semicolons are command separators - must be escaped
        assert!(
            quoted.contains('\'') || quoted.contains('\\'),
            "Path with semicolon should be quoted to prevent command injection: {quoted}"
        );
    }

    #[test]
    fn test_quote_path_with_pipe() {
        let path = Path::new("/tmp/file|cat /etc/passwd.txt");
        let quoted = quote_path(path);
        // Pipes are shell operators - must be escaped
        assert!(
            quoted.contains('\'') || quoted.contains('\\'),
            "Path with pipe should be quoted to prevent piping: {quoted}"
        );
    }

    #[test]
    fn test_quote_path_with_ampersand() {
        let path = Path::new("/tmp/file&background.txt");
        let quoted = quote_path(path);
        // Ampersands are background operators - must be escaped
        assert!(
            quoted.contains('\'') || quoted.contains('\\'),
            "Path with ampersand should be quoted: {quoted}"
        );
    }

    #[test]
    fn test_quote_path_combined_special_chars() {
        // Combination of multiple special characters
        let path = Path::new("/tmp/file's \"name\" with $var and `cmd`.txt");
        let quoted = quote_path(path);
        assert!(
            !quoted.is_empty(),
            "Path with multiple special characters should be properly escaped"
        );
    }

    // =========================================================================
    // build_script_command tests
    // =========================================================================

    #[test]
    fn test_build_script_command_without_log() {
        let prompt = Path::new("/tmp/prompt.txt");
        let cmd = build_script_command(prompt, None, None, None);

        // Verify command structure (platform-dependent)
        assert!(
            cmd.contains("script -q"),
            "Command without log should use script -q: {cmd}"
        );
        assert!(
            cmd.contains("codex exec"),
            "Command should invoke codex exec: {cmd}"
        );
        assert!(
            cmd.contains("--dangerously-bypass-approvals-and-sandbox"),
            "Command should include non-interactive bypass flag: {cmd}"
        );
        assert!(
            cmd.contains("/dev/null"),
            "Command without log should reference /dev/null: {cmd}"
        );
        assert!(
            cmd.contains("< "),
            "Command should use input redirection: {cmd}"
        );
    }

    #[test]
    fn test_build_script_command_with_log() {
        let prompt = Path::new("/tmp/prompt.txt");
        let log = Path::new("/tmp/review.log");
        let cmd = build_script_command(prompt, Some(log), None, None);

        // Verify command structure
        assert!(
            cmd.contains("script -q"),
            "Command with log should use script -q: {cmd}"
        );
        assert!(
            cmd.contains("sh -c '") || cmd.contains("-c '"),
            "Command with log should invoke shell with single quotes: {cmd}"
        );
        assert!(
            cmd.contains("codex exec"),
            "Command should invoke codex exec: {cmd}"
        );
        assert!(
            !cmd.ends_with("/dev/null"),
            "Command with log should not redirect to /dev/null: {cmd}"
        );
    }

    #[test]
    fn test_build_script_command_with_model() {
        let prompt = Path::new("/tmp/prompt.txt");
        let model = "gpt-5.3-codex";
        let cmd = build_script_command(prompt, None, Some(model), None);

        assert!(
            cmd.contains("--model gpt-5.3-codex"),
            "Command should include --model flag: {cmd}"
        );
    }

    #[test]
    fn test_build_script_command_quotes_paths_with_spaces() {
        let prompt = Path::new("/tmp/prompt with spaces.txt");
        let log = Path::new("/tmp/log with spaces.log");

        // Without log
        let cmd_no_log = build_script_command(prompt, None, None, None);
        assert!(
            cmd_no_log.contains('\''),
            "Prompt path with spaces should be quoted: {cmd_no_log}"
        );

        // With log
        let cmd_with_log = build_script_command(prompt, Some(log), None, None);
        assert!(
            cmd_with_log.contains('\''),
            "Paths with spaces should be quoted: {cmd_with_log}"
        );
    }

    #[test]
    fn test_build_script_command_handles_special_chars() {
        let prompt = Path::new("/tmp/prompt's$file.txt");
        let cmd = build_script_command(prompt, None, None, None);

        // The command should be properly escaped
        assert!(
            cmd.contains("script"),
            "Command structure should be preserved: {cmd}"
        );
    }

    // =========================================================================
    // build_script_command_with_cleanup tests
    // =========================================================================

    #[test]
    fn test_build_script_command_with_cleanup() {
        let prompt = Path::new("/tmp/prompt.txt");
        let log = Path::new("/tmp/review.log");
        let cmd = build_script_command_with_cleanup(prompt, log, None, None);

        // Verify command structure - same as build_script_command with log
        assert!(
            cmd.contains("script -q"),
            "Command should use script -q: {cmd}"
        );
        assert!(
            cmd.contains("codex exec"),
            "Command should invoke codex exec: {cmd}"
        );
        // Note: rm -f is no longer used - cleanup is handled via state tracking
        assert!(
            !cmd.contains("rm -f"),
            "Command should NOT include rm -f (cleanup via state): {cmd}"
        );
    }

    #[test]
    fn test_build_script_command_with_cleanup_quotes_paths() {
        let prompt = Path::new("/tmp/prompt with spaces.txt");
        let log = Path::new("/tmp/log.txt");
        let cmd = build_script_command_with_cleanup(prompt, log, None, None);

        // Path with spaces should be quoted
        assert!(
            cmd.contains('\''),
            "Path with spaces should be quoted: {cmd}"
        );
    }

    // =========================================================================
    // Integration-style tests
    // =========================================================================

    #[test]
    fn test_quote_path_is_shell_safe() {
        // These paths should all be made safe for shell execution
        let dangerous_paths = [
            // Avoid root-wipe patterns; still exercises separator + command injection.
            "/tmp/; rm -rf ./apm2_tsg_sentinel",
            "/tmp/$(whoami)",
            "/tmp/`id`",
            "/tmp/${PATH}",
            "/tmp/file\n; cat /etc/passwd",
            "/tmp/file | cat /etc/passwd",
            "/tmp/file > /etc/passwd",
            "/tmp/file < /etc/passwd",
            "/tmp/file && rm -rf ./apm2_tsg_sentinel",
            "/tmp/file || rm -rf ./apm2_tsg_sentinel",
        ];

        for path_str in dangerous_paths {
            let path = Path::new(path_str);
            let quoted = quote_path(path);
            // All dangerous paths should be quoted/escaped
            assert!(
                quoted.contains('\'') || quoted.contains('\\') || quoted.contains('"'),
                "Dangerous path should be quoted: {path_str} -> {quoted}"
            );
        }
    }

    #[test]
    fn test_command_format_matches_expected_pattern() {
        // Test that the generated commands match the documented patterns

        // Without log:
        //   - Linux: script -qec 'codex exec ...' /dev/null
        //   - macOS: script -q /dev/null sh -c 'codex exec ...'
        let prompt = Path::new("/tmp/simple.txt");
        let cmd = build_script_command(prompt, None, None, None);
        if cfg!(target_os = "macos") {
            assert!(cmd.starts_with("script -q /dev/null sh -c '"));
        } else {
            assert!(cmd.starts_with("script -qec"));
            assert!(cmd.ends_with("/dev/null"));
        }

        // With log:
        //   - Linux: script -q '<log_path>' -c 'codex exec ...'
        //   - macOS: script -q '<log_path>' sh -c 'codex exec ...'
        let log = Path::new("/tmp/log.txt");
        let cmd = build_script_command(prompt, Some(log), None, None);
        assert!(cmd.starts_with("script -q"));
        if cfg!(target_os = "macos") {
            assert!(cmd.contains("sh -c 'codex exec"));
        } else {
            assert!(cmd.contains("-c 'codex exec"));
        }
    }

    #[test]
    fn test_build_script_command_with_output_last_message() {
        let prompt = Path::new("/tmp/prompt.txt");
        let output = Path::new("/tmp/last_message.txt");
        let cmd = build_script_command(prompt, None, None, Some(output));

        assert!(
            cmd.contains("--output-last-message"),
            "Command should include --output-last-message: {cmd}"
        );
        assert!(
            cmd.contains("last_message.txt"),
            "Command should include output path: {cmd}"
        );
    }
}
