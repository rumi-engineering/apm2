//! Implementation of the `security-review-fix` command.
//!
//! This command runs an AI agent in a loop to fix security issues on the
//! current branch. The agent reviews the branch, edits files to fix issues,
//! and commits the fixes. The loop continues until either:
//! - The agent exits with code 0 (all issues resolved)
//! - The maximum number of iterations is reached
//!
//! # Usage
//!
//! ```bash
//! cargo xtask security-review-fix              # Run with default 10 iterations
//! cargo xtask security-review-fix TCK-00123    # Run for specific ticket
//! cargo xtask security-review-fix --max-iterations 5  # Custom iteration limit
//! ```
//!
//! # Workflow
//!
//! The typical workflow is:
//! 1. Start the command and let it run
//! 2. Check in every 3-5 minutes to monitor progress
//! 3. The command will exit when clean or when max iterations reached

use std::fs;
use std::process::Command;

use anyhow::{Context, Result, bail};
use tempfile::NamedTempFile;
use xshell::Shell;

use crate::shell_escape::build_ai_tool_command;
use crate::util::main_worktree;

/// Default maximum number of fix iterations.
pub const DEFAULT_MAX_ITERATIONS: u32 = 10;

/// Arguments for the security-review-fix command.
#[derive(Debug, Clone)]
pub struct SecurityReviewFixArgs {
    /// Optional ticket ID (e.g., TCK-00123)
    pub ticket_id: Option<String>,
    /// Maximum number of iterations before giving up
    pub max_iterations: u32,
}

impl Default for SecurityReviewFixArgs {
    fn default() -> Self {
        Self {
            ticket_id: None,
            max_iterations: DEFAULT_MAX_ITERATIONS,
        }
    }
}

/// Run the security review fix loop.
///
/// This function:
/// 1. Loads the security fix prompt
/// 2. Spawns an AI agent to review and fix security issues
/// 3. Checks the exit code: 0 = clean, non-zero = issues remain
/// 4. Loops until exit 0 or max iterations reached
///
/// # Arguments
///
/// * `args` - Command arguments including optional ticket ID and max iterations
///
/// # Errors
///
/// Returns an error if:
/// - The security fix prompt cannot be loaded
/// - The AI tool is not available
/// - Max iterations are reached without resolving all issues
pub fn run(args: &SecurityReviewFixArgs) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;
    let main_worktree_path = main_worktree(&sh)?;

    // Load the security fix prompt
    let prompt_path = main_worktree_path.join("documents/reviews/SECURITY_FIX_PROMPT.md");
    if !prompt_path.exists() {
        bail!(
            "Security fix prompt not found at: {}\n\
             Please create the prompt file first.",
            prompt_path.display()
        );
    }

    let prompt_content =
        fs::read_to_string(&prompt_path).context("Failed to read security fix prompt")?;

    // Substitute ticket ID if provided
    let prompt = args.ticket_id.as_ref().map_or_else(
        || prompt_content.replace("$TICKET_ID", ""),
        |ticket_id| prompt_content.replace("$TICKET_ID", ticket_id),
    );

    // Check if claude is available (preferred) or gemini
    let ai_tool = detect_ai_tool(&sh)?;

    println!("Security Review Fix Loop");
    println!("========================");
    println!("AI Tool: {ai_tool}");
    if let Some(ref ticket_id) = args.ticket_id {
        println!("Ticket: {ticket_id}");
    }
    println!("Max iterations: {}", args.max_iterations);
    println!();

    for iteration in 1..=args.max_iterations {
        println!(
            "[{}/{}] Running security fix agent...",
            iteration, args.max_iterations
        );

        let exit_code = spawn_security_fix_agent(&sh, &prompt, &ai_tool)?;

        if exit_code == 0 {
            println!();
            println!("All security issues resolved.");
            return Ok(());
        }

        println!("  Exit code: {exit_code} - issues remain, running again...");
        println!();
    }

    bail!(
        "Max iterations ({}) reached without resolving all security issues.\n\
         Manual intervention may be required.",
        args.max_iterations
    );
}

/// Detect which AI tool is available and executable.
///
/// Prefers claude (Claude Code) over gemini. Verifies executability by
/// running `--version` to ensure the tool is actually functional, not just
/// present in PATH.
fn detect_ai_tool(_sh: &Shell) -> Result<String> {
    // Check for claude first - verify it's executable
    if Command::new("claude")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return Ok("claude".to_string());
    }

    // Fall back to gemini - verify it's executable
    if Command::new("gemini")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return Ok("gemini".to_string());
    }

    bail!(
        "No AI tool found.\n\
         Please install either 'claude' (Claude Code) or 'gemini' CLI."
    );
}

/// Spawn the security fix agent and return its exit code.
///
/// The agent is given the prompt via stdin and runs in a PTY for full
/// tool access.
fn spawn_security_fix_agent(_sh: &Shell, prompt: &str, ai_tool: &str) -> Result<i32> {
    // Create a temp file for the prompt
    let mut prompt_file = NamedTempFile::new().context("Failed to create temp file for prompt")?;
    std::io::Write::write_all(&mut prompt_file, prompt.as_bytes())
        .context("Failed to write prompt to temp file")?;

    let prompt_path = prompt_file.path();

    // Get the appropriate flags for each AI tool
    let tool_flags = match ai_tool {
        "claude" => "--dangerously-skip-permissions",
        "gemini" => "--yolo",
        _ => bail!("Unknown AI tool: {ai_tool}"),
    };

    // Build the command using the secure shell_escape utility
    let shell_cmd = build_ai_tool_command(ai_tool, tool_flags, prompt_path, None);

    // Run the command
    let status = Command::new("sh")
        .args(["-c", &shell_cmd])
        .status()
        .context("Failed to spawn AI agent")?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = SecurityReviewFixArgs::default();
        assert!(args.ticket_id.is_none());
        assert_eq!(args.max_iterations, DEFAULT_MAX_ITERATIONS);
    }

    #[test]
    fn test_args_with_ticket() {
        let args = SecurityReviewFixArgs {
            ticket_id: Some("TCK-00123".to_string()),
            max_iterations: 5,
        };
        assert_eq!(args.ticket_id.as_deref(), Some("TCK-00123"));
        assert_eq!(args.max_iterations, 5);
    }
}
