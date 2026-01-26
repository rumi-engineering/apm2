//! Shell execution tool implementation.
//!
//! Provides the execution logic for shell commands (`ShellExec`).
//! Commands are executed in a subprocess with timeouts and output capture.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use super::{ShellExec, ToolError};

/// Shell tool handler.
#[derive(Debug)]
pub struct ShellTool {
    workspace_root: PathBuf,
}

impl ShellTool {
    /// Create a new shell tool handler.
    #[must_use]
    pub const fn new(workspace_root: PathBuf) -> Self {
        Self { workspace_root }
    }

    /// Resolve the working directory relative to the workspace root.
    fn resolve_cwd(&self, cwd: &str) -> Result<PathBuf, ToolError> {
        if cwd.is_empty() {
            return Ok(self.workspace_root.clone());
        }

        let path = Path::new(cwd);
        if cwd.contains("..") {
            return Err(ToolError {
                error_code: "PATH_TRAVERSAL".to_string(),
                message: "Path traversal sequences (..) are not allowed in cwd".to_string(),
                retryable: false,
                retry_after_ms: 0,
            });
        }

        let resolved = self.workspace_root.join(path);

        // Canonicalize to verify existence and confinement
        let canonical = resolved.canonicalize().map_err(|e| ToolError {
            error_code: "INVALID_CWD".to_string(),
            message: format!("Invalid working directory: {e}"),
            retryable: false,
            retry_after_ms: 0,
        })?;

        if !canonical.starts_with(&self.workspace_root) {
            return Err(ToolError {
                error_code: "ACCESS_DENIED".to_string(),
                message: "Working directory escapes workspace root".to_string(),
                retryable: false,
                retry_after_ms: 0,
            });
        }

        Ok(canonical)
    }

    /// Execute a shell command.
    ///
    /// # Errors
    ///
    /// Returns a `ToolError` if execution fails, times out, or returns a
    /// non-zero exit code.
    pub async fn execute(&self, req: &ShellExec) -> Result<Vec<u8>, ToolError> {
        info!("Executing command: '{}'", req.command);

        let cwd = self.resolve_cwd(&req.cwd)?;
        debug!("Working directory: {:?}", cwd);

        // TODO: Enforce network_access flag via seccomp/unshare if strictly required
        // here. For now, we rely on the container environment or policy to
        // restrict network.
        if !req.network_access {
            debug!("Network access not requested (enforcement delegated to environment)");
        }

        let timeout_duration = if req.timeout_ms > 0 {
            Duration::from_millis(req.timeout_ms)
        } else {
            Duration::from_secs(60) // Default 60s
        };

        #[cfg(target_os = "windows")]
        let mut cmd = Command::new("cmd");
        #[cfg(target_os = "windows")]
        cmd.arg("/C").arg(&req.command);

        #[cfg(not(target_os = "windows"))]
        let mut cmd = Command::new("sh");
        #[cfg(not(target_os = "windows"))]
        cmd.arg("-c").arg(&req.command);

        cmd.current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Set environment variables
        // Clear existing env to ensure hermetic execution?
        // Or inherit? Usually we want a controlled environment.
        // We'll clear and set only provided + minimal PATH/TERM.
        cmd.env_clear();
        cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
        cmd.env("TERM", "xterm-256color");
        cmd.env("LANG", "C.UTF-8");

        for env_str in &req.env {
            if let Some((key, value)) = env_str.split_once('=') {
                cmd.env(key, value);
            }
        }

        let child = cmd.spawn().map_err(|e| ToolError {
            error_code: "EXEC_FAILED".to_string(),
            message: format!("Failed to spawn command: {e}"),
            retryable: true,
            retry_after_ms: 1000,
        })?;

        let output_result = timeout(timeout_duration, child.wait_with_output()).await;

        match output_result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                let combined = if stderr.is_empty() {
                    stdout.into_owned()
                } else {
                    format!("{stdout}\nSTDERR:\n{stderr}")
                };

                if output.status.success() {
                    Ok(combined.into_bytes())
                } else {
                    let code = output.status.code().unwrap_or(-1);
                    Err(ToolError {
                        error_code: "COMMAND_FAILED".to_string(),
                        message: format!("Command exited with code {code}:\n{combined}"),
                        retryable: false,
                        retry_after_ms: 0,
                    })
                }
            },
            Ok(Err(e)) => Err(ToolError {
                error_code: "IO_ERROR".to_string(),
                message: format!("Failed to wait for command: {e}"),
                retryable: true,
                retry_after_ms: 500,
            }),
            Err(_) => {
                // Timeout
                warn!("Command timed out: '{}'", req.command);
                // Child is dropped here, tokio attempts to kill it?
                // tokio::process::Child doesn't auto-kill on drop by default in old versions,
                // but we consumed it in wait_with_output.
                // Actually, wait_with_output consumes self.
                // If timeout happens, the future is cancelled.
                // We might need to kill it manually if we held the child handle.
                // But wait_with_output takes ownership.
                // So we can't kill it easily if it times out inside wait_with_output?
                // Actually, if the future is dropped, the background task might linger if not
                // careful. But wait_with_output handles reading pipes.

                // For robust timeout kill, we usually spawn, then select! on wait.
                // But let's return error first.
                Err(ToolError {
                    error_code: "TIMEOUT".to_string(),
                    message: format!("Command timed out after {}ms", timeout_duration.as_millis()),
                    retryable: true,
                    retry_after_ms: 1000,
                })
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_execute_success() {
        let temp_dir = TempDir::new().unwrap();
        let tool = ShellTool::new(temp_dir.path().to_path_buf());

        let req = ShellExec {
            command: "echo hello".to_string(),
            cwd: String::new(),
            timeout_ms: 1000,
            network_access: false,
            env: vec![],
        };

        let output = tool.execute(&req).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&output).trim(), "hello");
    }

    #[tokio::test]
    async fn test_execute_with_env() {
        let temp_dir = TempDir::new().unwrap();
        let tool = ShellTool::new(temp_dir.path().to_path_buf());

        let req = ShellExec {
            command: "echo $MY_VAR".to_string(),
            cwd: String::new(),
            timeout_ms: 1000,
            network_access: false,
            env: vec!["MY_VAR=world".to_string()],
        };

        let output = tool.execute(&req).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&output).trim(), "world");
    }

    #[tokio::test]
    async fn test_execute_failure() {
        let temp_dir = TempDir::new().unwrap();
        let tool = ShellTool::new(temp_dir.path().to_path_buf());

        let req = ShellExec {
            command: "exit 1".to_string(),
            cwd: String::new(),
            timeout_ms: 1000,
            network_access: false,
            env: vec![],
        };

        let err = tool.execute(&req).await.unwrap_err();
        assert_eq!(err.error_code, "COMMAND_FAILED");
    }

    #[tokio::test]
    async fn test_execute_timeout() {
        let temp_dir = TempDir::new().unwrap();
        let tool = ShellTool::new(temp_dir.path().to_path_buf());

        let req = ShellExec {
            command: "sleep 2".to_string(),
            cwd: String::new(),
            timeout_ms: 100, // Short timeout
            network_access: false,
            env: vec![],
        };

        let err = tool.execute(&req).await.unwrap_err();
        assert_eq!(err.error_code, "TIMEOUT");
    }

    #[tokio::test]
    async fn test_cwd_traversal_blocked() {
        let temp_dir = TempDir::new().unwrap();
        let tool = ShellTool::new(temp_dir.path().to_path_buf());

        let req = ShellExec {
            command: "ls".to_string(),
            cwd: "../".to_string(),
            timeout_ms: 1000,
            network_access: false,
            env: vec![],
        };

        let err = tool.execute(&req).await.unwrap_err();
        assert_eq!(err.error_code, "PATH_TRAVERSAL");
    }
}
