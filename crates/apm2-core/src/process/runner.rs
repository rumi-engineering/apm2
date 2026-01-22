//! Process lifecycle management.
//!
//! Provides the `ProcessRunner` which manages a single process instance
//! lifecycle, including starting, stopping, and monitoring.

use std::process::ExitStatus;
use std::time::Duration;

use tokio::process::Child;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use super::spawner::spawn;
use super::{ProcessError, ProcessSpec, ProcessState};

/// Manages the lifecycle of a single process instance.
pub struct ProcessRunner {
    /// The process specification.
    spec: ProcessSpec,
    /// Instance index (0-based).
    instance: u32,
    /// The child process handle (if running).
    child: Option<Child>,
    /// Current process state.
    state: ProcessState,
    /// Current PID (if running).
    pid: Option<u32>,
}

impl ProcessRunner {
    /// Create a new process runner for a specification and instance index.
    #[must_use]
    pub const fn new(spec: ProcessSpec, instance: u32) -> Self {
        Self {
            spec,
            instance,
            child: None,
            state: ProcessState::Stopped { exit_code: None },
            pid: None,
        }
    }

    /// Get the display name for this runner (name-instance format for
    /// multi-instance).
    #[must_use]
    pub fn display_name(&self) -> String {
        if self.spec.instances > 1 {
            format!("{}-{}", self.spec.name, self.instance)
        } else {
            self.spec.name.clone()
        }
    }

    /// Start the process.
    ///
    /// # Errors
    ///
    /// Returns an error if the process is already running or fails to spawn.
    pub fn start(&mut self) -> Result<(), ProcessError> {
        if self.state.is_running() {
            return Err(ProcessError::InvalidState(format!(
                "process {} is already running",
                self.display_name()
            )));
        }

        self.state = ProcessState::Starting;
        info!("Starting process {}", self.display_name());

        let spawned = spawn(&self.spec)?;

        self.pid = Some(spawned.pid);
        self.child = Some(spawned.child);
        self.state = ProcessState::Running;

        info!(
            "Process {} started with PID {}",
            self.display_name(),
            spawned.pid
        );

        Ok(())
    }

    /// Stop the process gracefully with a timeout.
    ///
    /// Sends SIGTERM first, then SIGKILL after the timeout if the process
    /// hasn't exited.
    ///
    /// # Arguments
    ///
    /// * `graceful_timeout` - How long to wait for graceful shutdown before
    ///   force killing.
    ///
    /// # Errors
    ///
    /// Returns an error if the process is not running or signal delivery fails.
    pub async fn stop(&mut self, graceful_timeout: Duration) -> Result<(), ProcessError> {
        if !self.state.is_running() {
            return Err(ProcessError::InvalidState(format!(
                "process {} is not running",
                self.display_name()
            )));
        }

        self.state = ProcessState::Stopping;
        info!("Stopping process {}", self.display_name());

        let Some(pid) = self.pid else {
            // No PID means we lost track of the process
            self.state = ProcessState::Stopped { exit_code: None };
            self.child = None;
            return Ok(());
        };

        // Send SIGTERM
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;

            #[allow(clippy::cast_possible_wrap)] // PIDs won't exceed i32 range
            if let Err(e) = kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
                warn!("Failed to send SIGTERM to {}: {}", self.display_name(), e);
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix, we just kill the child directly
            if let Some(child) = &mut self.child {
                let _ = child.kill().await;
            }
        }

        // Wait for exit with timeout
        if let Some(child) = &mut self.child {
            match timeout(graceful_timeout, child.wait()).await {
                Ok(Ok(status)) => {
                    let exit_code = status.code();
                    debug!(
                        "Process {} exited gracefully with code {:?}",
                        self.display_name(),
                        exit_code
                    );
                    self.state = ProcessState::Stopped { exit_code };
                },
                Ok(Err(e)) => {
                    warn!("Error waiting for process {}: {}", self.display_name(), e);
                    self.state = ProcessState::Stopped { exit_code: None };
                },
                Err(_) => {
                    // Timeout - force kill
                    warn!(
                        "Process {} did not exit gracefully, sending SIGKILL",
                        self.display_name()
                    );
                    self.force_kill().await;
                },
            }
        }

        self.pid = None;
        self.child = None;

        info!("Process {} stopped", self.display_name());
        Ok(())
    }

    /// Force kill the process with SIGKILL.
    async fn force_kill(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.pid {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;

            #[allow(clippy::cast_possible_wrap)] // PIDs won't exceed i32 range
            if let Err(e) = kill(Pid::from_raw(pid as i32), Signal::SIGKILL) {
                warn!("Failed to send SIGKILL to {}: {}", self.display_name(), e);
            }
        }

        // Also try through the Child handle
        if let Some(child) = &mut self.child {
            let _ = child.kill().await;
            // Give it a moment to die
            let _ = timeout(Duration::from_millis(500), child.wait()).await;
        }

        self.state = ProcessState::Terminated;
    }

    /// Wait for the process to exit.
    ///
    /// Returns the exit status when the process terminates.
    /// Returns `None` if there is no running process.
    pub async fn wait(&mut self) -> Option<ExitStatus> {
        let child = self.child.as_mut()?;
        let status = child.wait().await.ok()?;

        let exit_code = status.code();

        // Determine if this was a crash or normal exit
        if status.success() {
            self.state = ProcessState::Stopped { exit_code };
        } else {
            self.state = ProcessState::Crashed { exit_code };
        }

        self.pid = None;
        Some(status)
    }

    /// Check if the process is still running (non-blocking).
    ///
    /// Returns `Some(ExitStatus)` if the process has exited, `None` if still
    /// running.
    pub fn try_wait(&mut self) -> Option<ExitStatus> {
        let child = self.child.as_mut()?;
        match child.try_wait() {
            Ok(Some(status)) => {
                let exit_code = status.code();
                if status.success() {
                    self.state = ProcessState::Stopped { exit_code };
                } else {
                    self.state = ProcessState::Crashed { exit_code };
                }
                self.pid = None;
                Some(status)
            },
            Ok(None) | Err(_) => None, // Still running or error checking
        }
    }

    /// Get the current process PID.
    #[must_use]
    pub const fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Get the current process state.
    #[must_use]
    pub const fn state(&self) -> &ProcessState {
        &self.state
    }

    /// Get the process specification.
    #[must_use]
    pub const fn spec(&self) -> &ProcessSpec {
        &self.spec
    }

    /// Get the instance index.
    #[must_use]
    pub const fn instance(&self) -> u32 {
        self.instance
    }

    /// Take ownership of the child process handle.
    ///
    /// This is useful for transferring the child to another manager.
    pub const fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore)] // Miri can't spawn processes
    #[tokio::test]
    async fn test_runner_start_stop() {
        let spec = ProcessSpec::builder()
            .name("test-sleep")
            .command("sleep")
            .args(["10"])
            .build();

        let mut runner = ProcessRunner::new(spec, 0);
        assert!(!runner.state().is_running());

        // Start
        runner.start().unwrap();
        assert!(runner.state().is_running());
        assert!(runner.pid().is_some());

        // Stop
        runner.stop(Duration::from_secs(1)).await.unwrap();
        assert!(!runner.state().is_running());
        assert!(runner.pid().is_none());
    }

    #[cfg_attr(miri, ignore)] // Miri can't spawn processes
    #[tokio::test]
    async fn test_runner_wait_for_exit() {
        let spec = ProcessSpec::builder()
            .name("test-short")
            .command("sh")
            .args(["-c", "exit 0"])
            .build();

        let mut runner = ProcessRunner::new(spec, 0);
        runner.start().unwrap();

        let status = runner.wait().await;
        assert!(status.is_some());
        assert!(status.unwrap().success());
        assert!(!runner.state().is_running());
    }

    #[cfg_attr(miri, ignore)] // Miri can't spawn processes
    #[tokio::test]
    async fn test_runner_crashed_exit() {
        let spec = ProcessSpec::builder()
            .name("test-fail")
            .command("sh")
            .args(["-c", "exit 1"])
            .build();

        let mut runner = ProcessRunner::new(spec, 0);
        runner.start().unwrap();

        let status = runner.wait().await;
        assert!(status.is_some());
        assert!(!status.unwrap().success());
        assert!(matches!(runner.state(), ProcessState::Crashed { .. }));
    }

    #[test]
    fn test_display_name_single_instance() {
        let spec = ProcessSpec::builder()
            .name("my-process")
            .command("echo")
            .instances(1)
            .build();

        let runner = ProcessRunner::new(spec, 0);
        assert_eq!(runner.display_name(), "my-process");
    }

    #[test]
    fn test_display_name_multi_instance() {
        let spec = ProcessSpec::builder()
            .name("my-process")
            .command("echo")
            .instances(3)
            .build();

        let runner = ProcessRunner::new(spec, 1);
        assert_eq!(runner.display_name(), "my-process-1");
    }
}
