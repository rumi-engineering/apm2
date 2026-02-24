//! Backend command builders for Codex and Gemini review processes.
//!
//! All builders return a [`SpawnCommand`] struct that holds a typed argv
//! (program + arguments) instead of a shell command string. This prevents
//! shell metacharacter injection by never passing untrusted data through
//! `sh -c` or equivalent shell-parsing boundaries.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::{fs, io};

use super::model_pool::normalize_gemini_model;
use super::types::ReviewBackend;

// ── SpawnCommand ────────────────────────────────────────────────────────────

/// Structured command descriptor that avoids shell parsing.
///
/// Instead of building a single shell command string and passing it through
/// `sh -lc`, callers construct a `SpawnCommand` and call
/// [`SpawnCommand::spawn`] which uses `std::process::Command` with typed argv.
#[derive(Debug, Clone)]
pub struct SpawnCommand {
    pub program: String,
    pub args: Vec<String>,
    /// Additional environment variables to set for the child process.
    pub env: Vec<(String, String)>,
    /// Path to the log file for stdout/stderr capture.
    pub log_path: PathBuf,
    /// If true, append to the log file rather than truncating.
    pub append_log: bool,
    /// Optional path to a file whose contents are piped to stdin.
    pub stdin_file: Option<PathBuf>,
}

impl SpawnCommand {
    /// Spawn the command, redirecting stdout and stderr to `log_path` and
    /// optionally piping `stdin_file` contents to stdin.
    ///
    /// This replaces the previous pattern of
    /// `Command::new("sh").args(["-lc", &cmd_string]).spawn()` with direct
    /// `Command::new(program).args(args)` execution, eliminating the shell
    /// parsing boundary entirely.
    pub fn spawn(&self) -> Result<std::process::Child, String> {
        let log_file = if self.append_log {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)
        } else {
            fs::File::create(&self.log_path)
        };

        let log_file = log_file
            .map_err(|err| format!("failed to open log file {}: {err}", self.log_path.display()))?;

        let stderr_log = log_file
            .try_clone()
            .map_err(|err| format!("failed to clone log file handle: {err}"))?;

        let stdin_cfg = match &self.stdin_file {
            Some(path) => {
                let f = fs::File::open(path).map_err(|err| {
                    format!("failed to open stdin file {}: {err}", path.display())
                })?;
                Stdio::from(f)
            },
            None => Stdio::null(),
        };

        let mut command = Command::new(&self.program);
        command.args(&self.args);
        for (key, value) in &self.env {
            command.env(key, value);
        }
        command
            .stdin(stdin_cfg)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr_log))
            .spawn()
            .map_err(|err| format!("failed to spawn {}: {err}", self.program))
    }
}

// ── Feature detection ───────────────────────────────────────────────────────

fn claude_supports_prompt_file_argument() -> bool {
    static HAS_PROMPT_FILE_FLAG: OnceLock<bool> = OnceLock::new();
    *HAS_PROMPT_FILE_FLAG.get_or_init(|| match Command::new("claude").arg("--help").output() {
        Ok(output) => {
            let mut text = String::new();
            text.push_str(&String::from_utf8_lossy(&output.stdout));
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            text.contains("--prompt-file")
        },
        Err(_) => false,
    })
}

// ── Initial-spawn builders ──────────────────────────────────────────────────

/// Build an initial spawn command for the Gemini backend.
pub fn build_gemini_spawn_command(
    prompt_path: &Path,
    log_path: &Path,
    model: &str,
) -> io::Result<SpawnCommand> {
    let prompt_content = fs::read_to_string(prompt_path)?;
    Ok(SpawnCommand {
        program: "gemini".to_string(),
        args: vec![
            "-m".to_string(),
            normalize_gemini_model(model).to_string(),
            "-y".to_string(),
            "-o".to_string(),
            "stream-json".to_string(),
            "-p".to_string(),
            prompt_content,
        ],
        env: Vec::new(),
        log_path: log_path.to_path_buf(),
        append_log: false,
        stdin_file: None,
    })
}

/// Build an initial spawn command for the given backend.
///
/// Returns a [`SpawnCommand`] that can be spawned directly via
/// [`SpawnCommand::spawn`] without any shell parsing.
pub fn build_spawn_command_for_backend(
    backend: ReviewBackend,
    prompt_path: &Path,
    log_path: &Path,
    model: &str,
    output_last_message_path: Option<&Path>,
) -> Result<SpawnCommand, String> {
    match backend {
        ReviewBackend::Codex => {
            let mut args = vec![
                "exec".to_string(),
                "--model".to_string(),
                model.to_string(),
                "--dangerously-bypass-approvals-and-sandbox".to_string(),
                "--json".to_string(),
            ];
            if let Some(capture_path) = output_last_message_path {
                args.push("--output-last-message".to_string());
                args.push(capture_path.display().to_string());
            }
            Ok(SpawnCommand {
                program: "codex".to_string(),
                args,
                env: Vec::new(),
                log_path: log_path.to_path_buf(),
                append_log: false,
                stdin_file: Some(prompt_path.to_path_buf()),
            })
        },
        ReviewBackend::Gemini => build_gemini_spawn_command(prompt_path, log_path, model)
            .map_err(|err| format!("failed to build gemini spawn command: {err}")),
        ReviewBackend::ClaudeCode => {
            let (program_args, stdin_file) = if claude_supports_prompt_file_argument() {
                (
                    vec![
                        "--prompt-file".to_string(),
                        prompt_path.display().to_string(),
                        "--model".to_string(),
                        model.to_string(),
                        "--output-format".to_string(),
                        "json".to_string(),
                        "--permission-mode".to_string(),
                        "plan".to_string(),
                    ],
                    None,
                )
            } else {
                (
                    vec![
                        "-p".to_string(),
                        "--model".to_string(),
                        model.to_string(),
                        "--output-format".to_string(),
                        "json".to_string(),
                        "--permission-mode".to_string(),
                        "plan".to_string(),
                    ],
                    Some(prompt_path.to_path_buf()),
                )
            };
            Ok(SpawnCommand {
                program: "claude".to_string(),
                args: program_args,
                env: Vec::new(),
                log_path: log_path.to_path_buf(),
                append_log: false,
                stdin_file,
            })
        },
    }
}

// ── Resume builders ─────────────────────────────────────────────────────────

/// Build a resume command for the given backend (no log-file wrapping).
pub fn build_resume_spawn_command_for_backend(
    backend: ReviewBackend,
    log_path: &Path,
    model: &str,
    resume_prompt_path: &Path,
) -> SpawnCommand {
    match backend {
        ReviewBackend::Codex => SpawnCommand {
            program: "codex".to_string(),
            args: vec![
                "exec".to_string(),
                "resume".to_string(),
                "--last".to_string(),
                "--dangerously-bypass-approvals-and-sandbox".to_string(),
                "--json".to_string(),
                "-".to_string(),
            ],
            env: Vec::new(),
            log_path: log_path.to_path_buf(),
            append_log: true,
            stdin_file: Some(resume_prompt_path.to_path_buf()),
        },
        ReviewBackend::Gemini => SpawnCommand {
            program: "gemini".to_string(),
            args: vec![
                "-m".to_string(),
                normalize_gemini_model(model).to_string(),
                "-y".to_string(),
                "--resume".to_string(),
                "latest".to_string(),
                "-p".to_string(),
                String::new(),
            ],
            env: Vec::new(),
            log_path: log_path.to_path_buf(),
            append_log: true,
            stdin_file: Some(resume_prompt_path.to_path_buf()),
        },
        ReviewBackend::ClaudeCode => SpawnCommand {
            program: "claude".to_string(),
            args: vec![
                "-p".to_string(),
                "--model".to_string(),
                model.to_string(),
                "--output-format".to_string(),
                "json".to_string(),
                "--permission-mode".to_string(),
                "plan".to_string(),
                "--resume".to_string(),
            ],
            env: Vec::new(),
            log_path: log_path.to_path_buf(),
            append_log: true,
            stdin_file: Some(resume_prompt_path.to_path_buf()),
        },
    }
}

// ── Deprecated string-based builders (preserved for test compatibility) ─────

/// Build the SHA-drift update message sent to the review agent on resume.
pub fn build_sha_update_message(pr_number: u32, old_sha: &str, new_sha: &str) -> String {
    format!(
        "CRITICAL: The PR HEAD has moved from {old_sha} to {new_sha}. Re-run `apm2 fac review prepare --pr {pr_number} --sha {new_sha}` and re-read the prepared diff. Update your review and publish a new comment targeting SHA {new_sha}. Your full prior analysis is preserved in this session."
    )
}

/// Build prompt content from a template file, substituting PR metadata.
pub fn build_prompt_content(
    prompt_template_path: &Path,
    pr_url: &str,
    pr_number: u32,
    head_sha: &str,
    owner: &str,
    repo: &str,
) -> Result<String, String> {
    let template = fs::read_to_string(prompt_template_path).map_err(|err| {
        format!(
            "failed to read prompt template {}: {err}",
            prompt_template_path.display()
        )
    })?;

    let pr_number_text = pr_number.to_string();
    Ok(template
        .replace("$PR_URL", pr_url)
        .replace("$PR_NUMBER", &pr_number_text)
        .replace("$HEAD_SHA", head_sha)
        .replace(concat!("{", "owner", "}"), owner)
        .replace(concat!("{", "repo", "}"), repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_command_codex_initial_has_correct_structure() {
        let prompt = Path::new("/tmp/prompt.md");
        let log = Path::new("/tmp/review.log");
        let capture = Path::new("/tmp/capture.md");

        let cmd = build_spawn_command_for_backend(
            ReviewBackend::Codex,
            prompt,
            log,
            "gpt-5.3-codex",
            Some(capture),
        )
        .expect("build codex command");

        assert_eq!(cmd.program, "codex");
        assert!(cmd.args.contains(&"exec".to_string()));
        assert!(cmd.args.contains(&"--json".to_string()));
        assert!(cmd.args.contains(&"--output-last-message".to_string()));
        assert!(cmd.args.contains(&capture.display().to_string()));
        assert_eq!(cmd.stdin_file, Some(prompt.to_path_buf()));
        assert!(!cmd.append_log);
    }

    #[test]
    fn spawn_command_gemini_initial_reads_prompt_content() {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let prompt_path = temp.path();
        fs::write(prompt_path, "test prompt content").expect("write prompt");
        let log = Path::new("/tmp/gemini_review.log");

        let cmd = build_spawn_command_for_backend(
            ReviewBackend::Gemini,
            prompt_path,
            log,
            "gemini-3-flash-preview",
            None,
        )
        .expect("build gemini command");

        assert_eq!(cmd.program, "gemini");
        assert!(cmd.args.contains(&"-m".to_string()));
        assert!(cmd.args.contains(&"gemini-3-flash-preview".to_string()));
        assert!(cmd.args.contains(&"-o".to_string()));
        assert!(cmd.args.contains(&"stream-json".to_string()));
        assert!(cmd.args.contains(&"-p".to_string()));
        assert!(cmd.args.contains(&"test prompt content".to_string()));
        assert!(cmd.stdin_file.is_none());
    }

    #[test]
    fn spawn_command_claude_initial_uses_prompt_file_or_stdin() {
        let prompt = Path::new("/tmp/prompt.md");
        let log = Path::new("/tmp/claude_review.log");

        let cmd = build_spawn_command_for_backend(
            ReviewBackend::ClaudeCode,
            prompt,
            log,
            "claude-3-7-sonnet",
            None,
        )
        .expect("build claude command");

        assert_eq!(cmd.program, "claude");
        assert!(cmd.args.contains(&"--output-format".to_string()));
        assert!(cmd.args.contains(&"json".to_string()));
        assert!(cmd.args.contains(&"--permission-mode".to_string()));
        assert!(cmd.args.contains(&"plan".to_string()));
        // Either --prompt-file or -p with stdin_file must be set
        let has_prompt_file_arg = cmd.args.contains(&"--prompt-file".to_string());
        let has_p_flag = cmd.args.contains(&"-p".to_string());
        assert!(
            has_prompt_file_arg || has_p_flag,
            "claude command must use --prompt-file or -p"
        );
    }

    #[test]
    fn spawn_command_resume_codex_appends_to_log() {
        let log = Path::new("/tmp/resume.log");
        let prompt = Path::new("/tmp/resume_prompt.md");
        let cmd = build_resume_spawn_command_for_backend(
            ReviewBackend::Codex,
            log,
            "gpt-5.3-codex",
            prompt,
        );

        assert_eq!(cmd.program, "codex");
        assert!(cmd.args.contains(&"resume".to_string()));
        assert!(cmd.args.contains(&"--last".to_string()));
        assert!(cmd.args.contains(&"-".to_string()));
        assert!(cmd.append_log);
        assert_eq!(cmd.stdin_file, Some(prompt.to_path_buf()));
    }

    #[test]
    fn spawn_command_resume_gemini_appends_to_log() {
        let log = Path::new("/tmp/resume.log");
        let prompt = Path::new("/tmp/resume_prompt.md");
        let cmd = build_resume_spawn_command_for_backend(
            ReviewBackend::Gemini,
            log,
            "gemini-3-flash-preview",
            prompt,
        );

        assert_eq!(cmd.program, "gemini");
        assert!(cmd.args.contains(&"--resume".to_string()));
        assert!(cmd.args.contains(&"latest".to_string()));
        assert!(cmd.args.contains(&String::new()));
        assert!(cmd.append_log);
        assert_eq!(cmd.stdin_file, Some(prompt.to_path_buf()));
    }

    #[test]
    fn spawn_command_resume_claude_appends_to_log() {
        let log = Path::new("/tmp/resume.log");
        let prompt = Path::new("/tmp/resume_prompt.md");
        let cmd = build_resume_spawn_command_for_backend(
            ReviewBackend::ClaudeCode,
            log,
            "claude-3-7-sonnet",
            prompt,
        );

        assert_eq!(cmd.program, "claude");
        assert!(cmd.args.contains(&"--resume".to_string()));
        assert!(cmd.append_log);
        assert_eq!(cmd.stdin_file, Some(prompt.to_path_buf()));
    }

    #[test]
    fn spawn_command_args_never_contain_shell_metacharacters_from_input() {
        let prompt = Path::new("/tmp/prompt.md");
        let log = Path::new("/tmp/review.log");
        let malicious_model = "gpt-5; rm -rf /";

        let cmd = build_spawn_command_for_backend(
            ReviewBackend::Codex,
            prompt,
            log,
            malicious_model,
            None,
        )
        .expect("build command with malicious model");

        // The malicious model string should appear as a single argument,
        // not split by shell parsing.
        assert!(cmd.args.contains(&malicious_model.to_string()));
        // No argument should be "rm" or "-rf" or "/" — those would only
        // appear if shell parsing split the string.
        assert!(!cmd.args.contains(&"rm".to_string()));
        assert!(!cmd.args.contains(&"-rf".to_string()));
    }
}
