//! Process spawning utilities.
//!
//! Provides functionality to spawn child processes with appropriate
//! configuration.

use std::process::Stdio;

use tokio::process::{Child, Command};

use super::{ProcessError, ProcessSpec};

/// A spawned process with its child handle and PID.
pub struct SpawnedProcess {
    /// The child process handle.
    pub child: Child,
    /// The OS process ID.
    pub pid: u32,
}

/// Spawn a process according to its specification.
///
/// # Arguments
///
/// * `spec` - The process specification defining what to run.
///
/// # Returns
///
/// A `SpawnedProcess` containing the child handle and PID.
///
/// # Errors
///
/// Returns `ProcessError::SpawnFailed` if the process cannot be spawned,
/// or if the PID cannot be obtained.
pub fn spawn(spec: &ProcessSpec) -> Result<SpawnedProcess, ProcessError> {
    let mut cmd = Command::new(&spec.command);

    cmd.args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);

    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }

    for (k, v) in &spec.env {
        cmd.env(k, v);
    }

    let child = cmd
        .spawn()
        .map_err(|e| ProcessError::SpawnFailed(e.to_string()))?;

    let pid = child
        .id()
        .ok_or_else(|| ProcessError::SpawnFailed("failed to get process ID".to_string()))?;

    Ok(SpawnedProcess { child, pid })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore)] // Miri can't spawn processes
    #[tokio::test]
    async fn test_spawn_simple_process() {
        let spec = ProcessSpec::builder()
            .name("test-echo")
            .command("echo")
            .args(["hello"])
            .build();

        let result = spawn(&spec);
        assert!(result.is_ok());

        let mut spawned = result.unwrap();
        assert!(spawned.pid > 0);

        // Wait for the process to complete
        let status = spawned.child.wait().await.unwrap();
        assert!(status.success());
    }

    #[cfg_attr(miri, ignore)] // Miri can't spawn processes
    #[tokio::test]
    async fn test_spawn_with_env() {
        let spec = ProcessSpec::builder()
            .name("test-env")
            .command("sh")
            .args(["-c", "echo $TEST_VAR"])
            .env("TEST_VAR", "test_value")
            .build();

        let result = spawn(&spec);
        assert!(result.is_ok());

        let mut spawned = result.unwrap();
        let status = spawned.child.wait().await.unwrap();
        assert!(status.success());
    }

    #[cfg_attr(miri, ignore)] // Miri can't spawn processes
    #[tokio::test]
    async fn test_spawn_invalid_command() {
        let spec = ProcessSpec::builder()
            .name("test-invalid")
            .command("nonexistent_command_12345")
            .build();

        let result = spawn(&spec);
        assert!(result.is_err());
    }
}
