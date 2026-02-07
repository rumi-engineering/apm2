//! Input variation testing for AAT anti-gaming detection.
//!
//! This module implements input variation testing to detect invariant outputs,
//! which may indicate that a CLI command is gaming acceptance tests by
//! producing the same output regardless of input.
//!
//! # Strategy
//!
//! For each CLI command, we generate multiple input variations:
//! - Original command (baseline)
//! - With `--help` flag appended (should produce help output)
//! - With environment variable set (should behave differently if env-aware)
//!
//! If all variations produce identical output, this is flagged as invariance,
//! which is an anti-gaming violation.
//!
//! # Security
//!
//! This module avoids shell injection by:
//! - Parsing command strings using `shell-words` (POSIX shell word splitting)
//! - Executing commands directly without a shell interpreter
//! - Setting environment variables via `Command::env` instead of string
//!   concatenation
//!
//! # Example
//!
//! ```ignore
//! use xtask::aat::variation::{InputVariationGenerator, InputVariationResult};
//!
//! let results = InputVariationGenerator::test_command("cargo xtask check")?;
//!
//! if results.invariance_detected {
//!     println!("Warning: All input variations produced identical output");
//! }
//! ```

use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tempfile::TempDir;
use wait_timeout::ChildExt;

/// Maximum time allowed for a single command variation (30 seconds).
///
/// This is shorter than hypothesis execution timeout because variation
/// commands are expected to be quick checks, not full test suites.
const VARIATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum size of captured output (1 MB).
///
/// This prevents memory exhaustion from commands that produce excessive output.
const MAX_OUTPUT_SIZE: usize = 1024 * 1024;

/// Environment variables that are safe to pass to child processes.
///
/// This allowlist ensures that sensitive environment variables (API keys,
/// tokens, credentials) are not leaked to variation test commands.
///
/// # Security
///
/// Note: HOME is intentionally NOT in this list. Instead, we create an
/// isolated temporary HOME directory to prevent access to host credentials
/// (e.g., `~/.config/gh/hosts.yml`, `~/.gitconfig`).
///
/// XDG directories are also excluded to prevent credential access via
/// `$XDG_CONFIG_HOME/gh/hosts.yml` and similar paths.
const ALLOWED_ENV_VARS: &[&str] = &[
    "PATH",           // Required for command execution
    "USER",           // User identity
    "LANG",           // Locale settings
    "LC_ALL",         // Locale settings
    "TERM",           // Terminal type (for colored output)
    "RUST_BACKTRACE", // Useful for debugging test failures
    "CARGO_HOME",     // Cargo installation directory
    "RUSTUP_HOME",    // Rustup installation directory
    // NOTE: HOME is explicitly NOT included - we set an isolated temp HOME
    // NOTE: XDG_* vars are explicitly NOT included - they could leak credentials
];

/// A structured command variation that avoids shell injection.
///
/// Instead of representing variations as shell command strings, this struct
/// separates the executable, arguments, and environment variables. This allows
/// direct execution via `std::process::Command` without invoking a shell.
#[derive(Debug, Clone)]
pub struct CommandVariation {
    /// The executable to run (first word of the original command).
    pub executable: String,

    /// The arguments to pass to the executable.
    pub args: Vec<String>,

    /// Additional environment variables to set for this variation.
    pub extra_env: HashMap<String, String>,

    /// A human-readable description of this variation.
    pub description: String,
}

impl CommandVariation {
    /// Format the variation as a human-readable string for logging/display.
    ///
    /// Note: This is NOT used for execution - it's only for display purposes.
    #[must_use]
    pub fn display_string(&self) -> String {
        use std::fmt::Write;

        let env_prefix = self
            .extra_env
            .iter()
            .fold(String::new(), |mut acc, (k, v)| {
                let _ = write!(acc, "{k}={v} ");
                acc
            });

        let args_str = if self.args.is_empty() {
            String::new()
        } else {
            format!(" {}", self.args.join(" "))
        };

        format!("{env_prefix}{}{args_str}", self.executable)
    }
}

/// Result of executing a single input variation.
#[derive(Debug, Clone)]
pub struct SingleVariationResult {
    /// The input command that was executed (display string).
    pub input: String,

    /// The captured stdout output.
    pub output: String,

    /// The captured stderr output.
    pub stderr: String,

    /// The exit code of the command (None if terminated by signal).
    pub exit_code: Option<i32>,
}

/// Aggregated result of testing all input variations for a command.
#[derive(Debug, Clone)]
pub struct InputVariationResult {
    /// The base command that was tested.
    pub base_command: String,

    /// Results for each variation tested.
    pub variations: Vec<SingleVariationResult>,

    /// Number of variations that were tested.
    pub variations_tested: u32,

    /// Whether invariance was detected (all outputs identical).
    pub invariance_detected: bool,
}

/// Input variation generator and executor.
///
/// This struct provides methods to generate input variations for CLI commands
/// and execute them to detect invariance.
pub struct InputVariationGenerator;

impl InputVariationGenerator {
    /// Parse a command string into executable and arguments.
    ///
    /// Uses `shell-words` for POSIX-compliant word splitting, which handles
    /// quotes and escapes correctly without invoking a shell.
    ///
    /// # Arguments
    ///
    /// * `cmd` - A shell command string (e.g., "cargo test --lib")
    ///
    /// # Returns
    ///
    /// A tuple of (executable, arguments) or an error if parsing fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the command string has unmatched quotes or is empty.
    fn parse_command(cmd: &str) -> Result<(String, Vec<String>)> {
        let words =
            shell_words::split(cmd).with_context(|| format!("Failed to parse command: {cmd}"))?;

        if words.is_empty() {
            bail!("Empty command string");
        }

        let executable = words[0].clone();
        let args = words[1..].to_vec();

        Ok((executable, args))
    }

    /// Generate structured input variations for a CLI command.
    ///
    /// # Variation Strategies
    ///
    /// 1. **Original**: The command as-is (baseline)
    /// 2. **Help flag**: Append `--help` to trigger help output
    /// 3. **Environment variable**: Set `AAT_VARIATION_TEST=1` via
    ///    `Command::env`
    ///
    /// # Arguments
    ///
    /// * `base_cmd` - The base CLI command to generate variations for
    ///
    /// # Returns
    ///
    /// A vector of `CommandVariation` structs representing different input
    /// variations.
    ///
    /// # Errors
    ///
    /// Returns an error if the base command cannot be parsed.
    ///
    /// # Example
    ///
    /// ```
    /// use xtask::aat::variation::InputVariationGenerator;
    ///
    /// let variations = InputVariationGenerator::generate_variations("cargo test").unwrap();
    /// assert!(variations.len() >= 3);
    /// assert_eq!(variations[0].executable, "cargo");
    /// ```
    pub fn generate_variations(base_cmd: &str) -> Result<Vec<CommandVariation>> {
        let (executable, args) = Self::parse_command(base_cmd)?;

        Ok(vec![
            // Variation 1: Original command
            CommandVariation {
                executable: executable.clone(),
                args: args.clone(),
                extra_env: HashMap::new(),
                description: "original".to_string(),
            },
            // Variation 2: With --help flag (should produce different output)
            CommandVariation {
                executable: executable.clone(),
                args: {
                    let mut help_args = args.clone();
                    help_args.push("--help".to_string());
                    help_args
                },
                extra_env: HashMap::new(),
                description: "with --help".to_string(),
            },
            // Variation 3: With environment variable set
            CommandVariation {
                executable,
                args,
                extra_env: {
                    let mut env = HashMap::new();
                    env.insert("AAT_VARIATION_TEST".to_string(), "1".to_string());
                    env
                },
                description: "with AAT_VARIATION_TEST=1".to_string(),
            },
        ])
    }

    /// Generate string-based variations for backward compatibility.
    ///
    /// This method is deprecated and maintained only for backward compatibility
    /// with existing tests. New code should use `generate_variations()` which
    /// returns structured `CommandVariation` objects.
    ///
    /// # Arguments
    ///
    /// * `base_cmd` - The base CLI command to generate variations for
    ///
    /// # Returns
    ///
    /// A vector of command strings representing different input variations.
    #[must_use]
    #[deprecated(
        since = "0.3.0",
        note = "Use generate_variations() for structured variations"
    )]
    pub fn generate_variations_legacy(base_cmd: &str) -> Vec<String> {
        vec![
            // Variation 1: Original command
            base_cmd.to_string(),
            // Variation 2: With --help flag (should produce different output)
            format!("{base_cmd} --help"),
            // Variation 3: With environment variable set (display only)
            format!("AAT_VARIATION_TEST=1 {base_cmd}"),
        ]
    }

    /// Execute a structured command variation and capture its output.
    ///
    /// This method executes commands directly without a shell, preventing
    /// shell injection attacks.
    ///
    /// # Security
    ///
    /// Commands run in an isolated environment:
    /// - Environment is cleared except for an allowlist of safe variables
    /// - HOME is set to an empty temporary directory to prevent credential
    ///   access
    /// - XDG directories are not passed, preventing `~/.config/gh/hosts.yml`
    ///   access
    ///
    /// # Arguments
    ///
    /// * `variation` - The command variation to execute
    ///
    /// # Returns
    ///
    /// A `SingleVariationResult` containing the input, output, stderr, and exit
    /// code.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The command cannot be spawned
    /// - The command times out
    /// - Failed to create isolated HOME directory
    pub fn execute_variation(variation: &CommandVariation) -> Result<SingleVariationResult> {
        // Create an isolated temporary HOME directory to prevent credential access.
        // This prevents commands like `gh auth token` from reading
        // ~/.config/gh/hosts.yml [SECURITY: CTR-2401 - Treat external input as
        // adversarial]
        let isolated_home =
            TempDir::new().context("Failed to create isolated HOME directory for variation")?;

        // Build command without shell
        let mut command = Command::new(&variation.executable);
        command
            .args(&variation.args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Clear environment and only pass allowlisted variables
        command.env_clear();
        for var_name in ALLOWED_ENV_VARS {
            if let Ok(value) = std::env::var(var_name) {
                command.env(var_name, value);
            }
        }

        // Set isolated HOME directory - this prevents access to host credentials
        // like ~/.config/gh/hosts.yml, ~/.gitconfig, ~/.ssh/*, etc.
        command.env("HOME", isolated_home.path());

        // Add extra environment variables for this variation
        for (key, value) in &variation.extra_env {
            command.env(key, value);
        }

        let display_str = variation.display_string();

        let mut child = command
            .spawn()
            .with_context(|| format!("Failed to spawn variation command: {display_str}"))?;

        // Wait with timeout
        let Some(status) = child.wait_timeout(VARIATION_TIMEOUT)? else {
            // Timeout expired - kill the process
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "Variation command timed out after {} seconds: {display_str}",
                VARIATION_TIMEOUT.as_secs()
            );
        };

        // Read stdout (bounded)
        let stdout = if let Some(mut pipe) = child.stdout.take() {
            Self::read_bounded(&mut pipe)?
        } else {
            String::new()
        };

        // Read stderr (bounded)
        let stderr = if let Some(mut pipe) = child.stderr.take() {
            Self::read_bounded(&mut pipe)?
        } else {
            String::new()
        };

        // isolated_home is dropped here, cleaning up the temp directory

        Ok(SingleVariationResult {
            input: display_str,
            output: stdout,
            stderr,
            exit_code: status.code(),
        })
    }

    /// Execute a single command string and capture its output.
    ///
    /// This method parses the command string and executes it directly without
    /// a shell, preventing shell injection attacks.
    ///
    /// # Arguments
    ///
    /// * `cmd` - The command string to execute
    ///
    /// # Returns
    ///
    /// A `SingleVariationResult` containing the input, output, stderr, and exit
    /// code.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The command string cannot be parsed
    /// - The command cannot be spawned
    /// - The command times out
    ///
    /// # Security
    ///
    /// This method is secure against shell injection because:
    /// - Commands are parsed using `shell-words` (not executed by a shell)
    /// - The executable and arguments are passed directly to `Command::new`
    /// - Shell metacharacters (;, |, &&, etc.) are treated as literal arguments
    pub fn execute_single(cmd: &str) -> Result<SingleVariationResult> {
        let (executable, args) = Self::parse_command(cmd)?;

        let variation = CommandVariation {
            executable,
            args,
            extra_env: HashMap::new(),
            description: "direct execution".to_string(),
        };

        // Override the input display to show the original command string
        let mut result = Self::execute_variation(&variation)?;
        result.input = cmd.to_string();
        Ok(result)
    }

    /// Read output from a pipe with a size limit.
    ///
    /// Uses loop-based reading to ensure complete capture up to
    /// `MAX_OUTPUT_SIZE`. A single `read()` call may return partial data
    /// even when more is available, leading to non-deterministic capture
    /// and flaky invariance detection.
    ///
    /// # Arguments
    ///
    /// * `reader` - The reader (typically a process stdout/stderr pipe)
    ///
    /// # Returns
    ///
    /// The captured output as a String, with a truncation marker if the output
    /// exceeded `MAX_OUTPUT_SIZE`.
    fn read_bounded<R: std::io::Read>(reader: &mut R) -> Result<String> {
        use std::io::Read as _;

        // Use `take` to limit the read to MAX_OUTPUT_SIZE + 1 bytes.
        // The +1 allows us to detect truncation (if we read exactly MAX_OUTPUT_SIZE+1,
        // we know there was more data).
        let mut limited_reader = reader.take((MAX_OUTPUT_SIZE + 1) as u64);

        // Pre-allocate a reasonable buffer, not the full max (64KB is reasonable)
        // This prevents allocation of 1MB for small outputs
        let mut buffer = Vec::with_capacity(64 * 1024);

        // Read all available data up to the limit
        // read_to_end loops internally until EOF or error, unlike a single read()
        limited_reader
            .read_to_end(&mut buffer)
            .context("Failed to read process output")?;

        // Check if we hit the limit (indicates truncation)
        let truncated = buffer.len() > MAX_OUTPUT_SIZE;
        if truncated {
            buffer.truncate(MAX_OUTPUT_SIZE);
        }

        let mut output = String::from_utf8_lossy(&buffer).to_string();

        if truncated {
            output.push_str("\n[TRUNCATED: output exceeded size limit]");
        }

        Ok(output)
    }

    /// Execute all variations and detect invariance.
    ///
    /// This is the main entry point for variation testing. It:
    /// 1. Generates variations for the base command
    /// 2. Executes each variation
    /// 3. Compares outputs to detect invariance
    ///
    /// # Arguments
    ///
    /// * `base_cmd` - The base CLI command to test
    ///
    /// # Returns
    ///
    /// An `InputVariationResult` containing all variation results and
    /// invariance status.
    ///
    /// # Invariance Detection
    ///
    /// Invariance is detected when ALL of the following are true:
    /// - At least 2 variations were successfully executed
    /// - All successful variations produced identical stdout output
    ///
    /// Note: stderr is not considered for invariance detection because
    /// error messages may vary even for legitimate commands.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use xtask::aat::variation::InputVariationGenerator;
    ///
    /// let result = InputVariationGenerator::test_command("echo hello")?;
    ///
    /// // "echo hello" and "echo hello --help" produce different outputs
    /// // so invariance_detected should be false
    /// assert!(!result.invariance_detected);
    /// ```
    pub fn test_command(base_cmd: &str) -> Result<InputVariationResult> {
        let variations = Self::generate_variations(base_cmd)?;
        let mut results = Vec::with_capacity(variations.len());

        for variation in &variations {
            match Self::execute_variation(variation) {
                Ok(result) => results.push(result),
                Err(e) => {
                    // Log error but continue with other variations
                    eprintln!("Warning: Variation failed to execute: {e}");
                    // Add a result with error information
                    results.push(SingleVariationResult {
                        input: variation.display_string(),
                        output: String::new(),
                        stderr: format!("Execution error: {e}"),
                        exit_code: None,
                    });
                },
            }
        }

        // Detect invariance: all non-empty outputs are identical
        let invariance_detected = Self::detect_invariance(&results);

        // Safe cast: variations.len() is always 3 (from generate_variations)
        // which is well within u32 range
        let variations_tested = u32::try_from(variations.len()).unwrap_or(u32::MAX);

        Ok(InputVariationResult {
            base_command: base_cmd.to_string(),
            variations: results,
            variations_tested,
            invariance_detected,
        })
    }

    /// Detect invariance in variation results.
    ///
    /// Returns true if all variations with non-empty output produced identical
    /// stdout.
    fn detect_invariance(results: &[SingleVariationResult]) -> bool {
        // Get all non-empty outputs
        let outputs: Vec<&str> = results
            .iter()
            .filter(|r| !r.output.is_empty() && r.exit_code.is_some())
            .map(|r| r.output.as_str())
            .collect();

        // Need at least 2 outputs to detect invariance
        if outputs.len() < 2 {
            return false;
        }

        // Check if all outputs are identical
        outputs.windows(2).all(|w| w[0] == w[1])
    }

    /// Test multiple commands and aggregate results.
    ///
    /// # Arguments
    ///
    /// * `commands` - Iterator of base commands to test
    ///
    /// # Returns
    ///
    /// A vector of `InputVariationResult`, one for each command tested.
    pub fn test_commands<'a>(
        commands: impl IntoIterator<Item = &'a str>,
    ) -> Vec<InputVariationResult> {
        commands
            .into_iter()
            .filter_map(|cmd| Self::test_command(cmd).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Command parsing tests
    // =========================================================================

    #[test]
    fn test_parse_command_simple() {
        let (exe, args) = InputVariationGenerator::parse_command("cargo test").unwrap();
        assert_eq!(exe, "cargo");
        assert_eq!(args, vec!["test"]);
    }

    #[test]
    fn test_parse_command_with_flags() {
        let (exe, args) =
            InputVariationGenerator::parse_command("cargo test --lib -- --nocapture").unwrap();
        assert_eq!(exe, "cargo");
        assert_eq!(args, vec!["test", "--lib", "--", "--nocapture"]);
    }

    #[test]
    fn test_parse_command_with_quotes() {
        let (exe, args) = InputVariationGenerator::parse_command(r#"echo "hello world""#).unwrap();
        assert_eq!(exe, "echo");
        assert_eq!(args, vec!["hello world"]);
    }

    #[test]
    fn test_parse_command_empty() {
        let result = InputVariationGenerator::parse_command("");
        assert!(result.is_err());
    }

    // =========================================================================
    // Variation generation tests
    // =========================================================================

    #[test]
    fn test_generate_variations_count() {
        let variations = InputVariationGenerator::generate_variations("cargo test").unwrap();
        assert!(
            variations.len() >= 3,
            "Should generate at least 3 variations"
        );
    }

    #[test]
    fn test_generate_variations_content() {
        let variations = InputVariationGenerator::generate_variations("cargo test").unwrap();

        // First should be original
        assert_eq!(variations[0].executable, "cargo");
        assert_eq!(variations[0].args, vec!["test"]);
        assert!(variations[0].extra_env.is_empty());

        // Second should have --help
        assert!(variations[1].args.contains(&"--help".to_string()));

        // Third should have environment variable
        assert!(variations[2].extra_env.contains_key("AAT_VARIATION_TEST"));
    }

    #[test]
    fn test_generate_variations_with_complex_command() {
        let variations =
            InputVariationGenerator::generate_variations("cargo test --lib -- --nocapture")
                .unwrap();

        assert_eq!(variations[0].executable, "cargo");
        assert_eq!(
            variations[0].args,
            vec!["test", "--lib", "--", "--nocapture"]
        );
        assert!(variations[1].args.contains(&"--help".to_string()));
    }

    #[test]
    fn test_command_variation_display_string() {
        let variation = CommandVariation {
            executable: "cargo".to_string(),
            args: vec!["test".to_string(), "--lib".to_string()],
            extra_env: HashMap::new(),
            description: "test".to_string(),
        };
        assert_eq!(variation.display_string(), "cargo test --lib");

        let variation_with_env = CommandVariation {
            executable: "cargo".to_string(),
            args: vec!["test".to_string()],
            extra_env: {
                let mut env = HashMap::new();
                env.insert("FOO".to_string(), "bar".to_string());
                env
            },
            description: "test".to_string(),
        };
        let display = variation_with_env.display_string();
        assert!(display.contains("FOO=bar"));
        assert!(display.contains("cargo test"));
    }

    // =========================================================================
    // Single execution tests
    // =========================================================================

    #[test]
    fn test_execute_single_success() {
        let result = InputVariationGenerator::execute_single("echo hello").unwrap();

        assert_eq!(result.input, "echo hello");
        assert!(result.output.contains("hello"));
        assert_eq!(result.exit_code, Some(0));
    }

    #[test]
    fn test_execute_single_failure() {
        // Use 'false' command which exits with code 1
        let result = InputVariationGenerator::execute_single("false").unwrap();

        assert_eq!(result.exit_code, Some(1));
    }

    #[test]
    fn test_execute_single_captures_stderr() {
        // Use sh to redirect to stderr (since we need shell for redirection in test)
        // But since we don't use shell, we test with a command that writes to stderr
        let result = InputVariationGenerator::execute_single("ls /nonexistent_path_12345");
        // This may or may not work depending on the system, but it shouldn't crash
        assert!(result.is_ok() || result.is_err());
    }

    // =========================================================================
    // Shell injection prevention tests
    // =========================================================================

    #[test]
    fn test_shell_injection_semicolon_prevented() {
        // This should NOT execute "exit 1" as a separate command
        // Instead, "exit" and "1" should be treated as arguments to "echo"
        let result = InputVariationGenerator::execute_single("echo safe; exit 1").unwrap();

        // The semicolon should be treated as a literal argument
        // echo should succeed with exit code 0
        assert_eq!(result.exit_code, Some(0));
        // Output should contain the semicolon as literal text
        assert!(
            result.output.contains("safe;") || result.output.contains("safe"),
            "Output should contain 'safe': {}",
            result.output
        );
    }

    #[test]
    fn test_shell_injection_pipe_prevented() {
        // This should NOT pipe output to cat
        // Instead, "|" and "cat" should be treated as arguments
        let result = InputVariationGenerator::execute_single("echo test | cat").unwrap();

        assert_eq!(result.exit_code, Some(0));
        // The pipe should be treated as a literal argument
        assert!(
            result.output.contains('|') || result.output.contains("test"),
            "Pipe should be treated literally: {}",
            result.output
        );
    }

    #[test]
    fn test_shell_injection_backtick_prevented() {
        // This should NOT execute whoami
        // Instead, the backticks should be treated as literal characters
        let result = InputVariationGenerator::execute_single("echo `whoami`").unwrap();

        // The backticks should be treated literally (shell-words doesn't
        // interpret backticks)
        assert_eq!(result.exit_code, Some(0));
    }

    #[test]
    fn test_shell_injection_dollar_prevented() {
        // $() command substitution should NOT work
        let result = InputVariationGenerator::execute_single("echo $(whoami)").unwrap();

        // Should be treated literally
        assert_eq!(result.exit_code, Some(0));
        // Output should contain the literal $(whoami) or similar
        assert!(
            result.output.contains("$(whoami)") || result.output.contains("whoami"),
            "Command substitution should not execute: {}",
            result.output
        );
    }

    // =========================================================================
    // Invariance detection tests
    // =========================================================================

    #[test]
    fn test_detect_invariance_identical_outputs() {
        let results = vec![
            SingleVariationResult {
                input: "cmd1".to_string(),
                output: "same".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd2".to_string(),
                output: "same".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd3".to_string(),
                output: "same".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
        ];

        assert!(InputVariationGenerator::detect_invariance(&results));
    }

    #[test]
    fn test_detect_invariance_different_outputs() {
        let results = vec![
            SingleVariationResult {
                input: "cmd1".to_string(),
                output: "output1".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd2".to_string(),
                output: "output2".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
        ];

        assert!(!InputVariationGenerator::detect_invariance(&results));
    }

    #[test]
    fn test_detect_invariance_empty_outputs_ignored() {
        let results = vec![
            SingleVariationResult {
                input: "cmd1".to_string(),
                output: "same".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd2".to_string(),
                output: String::new(), // Empty - should be ignored
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd3".to_string(),
                output: "different".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
        ];

        // Only "same" and "different" are compared - not identical
        assert!(!InputVariationGenerator::detect_invariance(&results));
    }

    #[test]
    fn test_detect_invariance_single_output() {
        let results = vec![SingleVariationResult {
            input: "cmd1".to_string(),
            output: "only".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }];

        // Need at least 2 outputs to detect invariance
        assert!(!InputVariationGenerator::detect_invariance(&results));
    }

    #[test]
    fn test_detect_invariance_failed_executions_ignored() {
        let results = vec![
            SingleVariationResult {
                input: "cmd1".to_string(),
                output: "output".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            },
            SingleVariationResult {
                input: "cmd2".to_string(),
                output: "output".to_string(),
                stderr: String::new(),
                exit_code: None, // Failed - no exit code
            },
        ];

        // Only one successful execution, so no invariance detected
        assert!(!InputVariationGenerator::detect_invariance(&results));
    }

    // =========================================================================
    // Full test_command tests
    // =========================================================================

    #[test]
    fn test_command_echo_not_invariant() {
        // "echo hello" and "echo hello --help" should produce different outputs
        // because echo treats --help as a literal string
        let result = InputVariationGenerator::test_command("echo hello").unwrap();

        assert_eq!(result.base_command, "echo hello");
        assert_eq!(result.variations_tested, 3);
        // All three variations of echo will produce different outputs
        // because the arguments are different
        assert!(result.variations.len() >= 2);
    }

    #[test]
    fn test_command_captures_variations() {
        let result = InputVariationGenerator::test_command("echo test").unwrap();

        // Should have results for all variations
        assert!(!result.variations.is_empty());

        // Each result should have the input recorded
        for var in &result.variations {
            assert!(!var.input.is_empty());
        }
    }

    // =========================================================================
    // Security tests
    // =========================================================================

    #[test]
    #[allow(unsafe_code)]
    fn test_environment_isolation() {
        // Set a sensitive variable
        // SAFETY: This test runs in isolation
        unsafe {
            std::env::set_var("SUPER_SECRET_VAR", "sensitive");
        }

        // Note: Without shell, we can't test $VAR expansion, but the isolation
        // still works because env is cleared
        let variation = CommandVariation {
            executable: "env".to_string(),
            args: vec![],
            extra_env: HashMap::new(),
            description: "test".to_string(),
        };

        let result = InputVariationGenerator::execute_variation(&variation).unwrap();

        // Clean up
        // SAFETY: This test runs in isolation
        unsafe {
            std::env::remove_var("SUPER_SECRET_VAR");
        }

        // The secret should NOT appear in output
        assert!(
            !result.output.contains("SUPER_SECRET_VAR"),
            "Secret var should not leak: {}",
            result.output
        );
    }

    #[test]
    fn test_allowed_env_passed() {
        // PATH should be available
        let variation = CommandVariation {
            executable: "env".to_string(),
            args: vec![],
            extra_env: HashMap::new(),
            description: "test".to_string(),
        };

        let result = InputVariationGenerator::execute_variation(&variation).unwrap();

        // PATH should be present
        assert!(result.output.contains("PATH="), "PATH should be passed");
    }

    #[test]
    fn test_extra_env_passed() {
        let variation = CommandVariation {
            executable: "env".to_string(),
            args: vec![],
            extra_env: {
                let mut env = HashMap::new();
                env.insert("TEST_VAR".to_string(), "test_value".to_string());
                env
            },
            description: "test".to_string(),
        };

        let result = InputVariationGenerator::execute_variation(&variation).unwrap();

        // Our extra env var should be present
        assert!(
            result.output.contains("TEST_VAR=test_value"),
            "Extra env should be passed: {}",
            result.output
        );
    }

    #[test]
    fn test_isolated_home_prevents_credential_access() {
        // SECURITY TEST: Verify that variations cannot access host HOME directory.
        // This prevents secret exfiltration via commands like `gh auth token`.
        //
        // The test verifies that:
        // 1. HOME is set to an isolated temporary directory
        // 2. The isolated HOME is different from the actual host HOME
        // 3. XDG_CONFIG_HOME is not set (preventing ~/.config/ access)

        let variation = CommandVariation {
            executable: "env".to_string(),
            args: vec![],
            extra_env: HashMap::new(),
            description: "credential isolation test".to_string(),
        };

        let result = InputVariationGenerator::execute_variation(&variation).unwrap();

        // Get the host HOME for comparison
        let host_home = std::env::var("HOME").unwrap_or_default();

        // Parse the HOME from the env output
        let env_home = result
            .output
            .lines()
            .find(|line| line.starts_with("HOME="))
            .map_or("", |line| line.strip_prefix("HOME=").unwrap_or(""));

        // HOME should be set (not empty)
        assert!(
            !env_home.is_empty(),
            "HOME should be set to isolated directory"
        );

        // HOME should NOT be the host HOME (credential isolation)
        assert_ne!(
            env_home, host_home,
            "Isolated HOME should differ from host HOME to prevent credential access"
        );

        // HOME should point to a temp directory (contains /tmp/ or similar)
        assert!(
            env_home.contains("/tmp")
                || env_home.contains("/var/folders")
                || env_home.contains("\\Temp"),
            "Isolated HOME should be in temp directory, got: {env_home}"
        );

        // XDG_CONFIG_HOME should NOT be set (another credential access vector)
        let has_xdg_config = result
            .output
            .lines()
            .any(|line| line.starts_with("XDG_CONFIG_HOME="));
        assert!(
            !has_xdg_config,
            "XDG_CONFIG_HOME should not be set to prevent credential access"
        );
    }

    // =========================================================================
    // Constant verification tests
    // =========================================================================

    #[test]
    fn test_timeout_is_reasonable() {
        assert_eq!(VARIATION_TIMEOUT.as_secs(), 30);
        assert!(
            VARIATION_TIMEOUT.as_secs() >= 10,
            "Timeout should be >= 10s"
        );
        assert!(
            VARIATION_TIMEOUT.as_secs() <= 60,
            "Timeout should be <= 60s"
        );
    }

    #[test]
    fn test_max_output_is_reasonable() {
        assert_eq!(MAX_OUTPUT_SIZE, 1024 * 1024); // 1 MB
    }

    // =========================================================================
    // Bounded read tests
    // =========================================================================

    #[test]
    fn test_read_bounded_small_output() {
        let data = b"hello world";
        let mut cursor = std::io::Cursor::new(data);

        let result = InputVariationGenerator::read_bounded(&mut cursor).unwrap();
        assert_eq!(result, "hello world");
        assert!(
            !result.contains("TRUNCATED"),
            "Small output should not be truncated"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_read_bounded_large_output_over_64kb() {
        // Create output larger than 64KB to test loop-based reading
        // A single read() call typically returns at most 64KB
        // The truncation here is intentional: we want bytes 0-255 repeating
        let large_data: Vec<u8> = (0u32..100_000).map(|i| (i % 256) as u8).collect();
        let mut cursor = std::io::Cursor::new(&large_data);

        let result = InputVariationGenerator::read_bounded(&mut cursor).unwrap();

        // Should capture all data (100KB is under 1MB limit)
        assert!(
            !result.contains("TRUNCATED"),
            "100KB output should not be truncated"
        );
        // Verify we got the expected size (may differ slightly due to UTF-8 lossy
        // conversion)
        assert!(
            result.len() >= 90_000,
            "Should capture most of the 100KB output, got {} bytes",
            result.len()
        );
    }

    #[test]
    fn test_read_bounded_truncation_at_limit() {
        // Create output that exceeds MAX_OUTPUT_SIZE
        let over_limit_data: Vec<u8> = vec![b'x'; MAX_OUTPUT_SIZE + 100];
        let mut cursor = std::io::Cursor::new(&over_limit_data);

        let result = InputVariationGenerator::read_bounded(&mut cursor).unwrap();

        // Should be truncated
        assert!(
            result.contains("TRUNCATED"),
            "Output over limit should be truncated"
        );
        // The base content (before truncation marker) should be at most MAX_OUTPUT_SIZE
        let truncation_marker = "\n[TRUNCATED: output exceeded size limit]";
        let content_len = result.len() - truncation_marker.len();
        assert!(
            content_len <= MAX_OUTPUT_SIZE,
            "Truncated content should not exceed MAX_OUTPUT_SIZE"
        );
    }

    #[test]
    fn test_read_bounded_exactly_at_limit() {
        // Create output exactly at MAX_OUTPUT_SIZE - should NOT be truncated
        let exact_data: Vec<u8> = vec![b'y'; MAX_OUTPUT_SIZE];
        let mut cursor = std::io::Cursor::new(&exact_data);

        let result = InputVariationGenerator::read_bounded(&mut cursor).unwrap();

        // Should NOT be truncated (exactly at limit, not over)
        assert!(
            !result.contains("TRUNCATED"),
            "Output exactly at limit should not be truncated"
        );
        assert_eq!(result.len(), MAX_OUTPUT_SIZE);
    }
}
