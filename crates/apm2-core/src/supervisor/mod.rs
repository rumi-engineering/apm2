//! Supervision module.
//!
//! Provides the core supervision logic for managing process lifecycles.

use std::collections::HashMap;

use crate::process::{ProcessHandle, ProcessId, ProcessSpec, ProcessState};
use crate::restart::RestartManager;
use crate::shutdown::ShutdownManager;

/// Supervisor that manages a collection of processes.
#[derive(Debug)]
pub struct Supervisor {
    /// Process specifications by ID.
    specs: HashMap<ProcessId, ProcessSpec>,

    /// Process handles by (`spec_id`, `instance_index`).
    handles: HashMap<(ProcessId, u32), ProcessHandle>,

    /// Restart managers by (`spec_id`, `instance_index`).
    restart_managers: HashMap<(ProcessId, u32), RestartManager>,

    /// Shutdown managers by (`spec_id`, `instance_index`).
    shutdown_managers: HashMap<(ProcessId, u32), ShutdownManager>,
}

impl Supervisor {
    /// Create a new supervisor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            specs: HashMap::new(),
            handles: HashMap::new(),
            restart_managers: HashMap::new(),
            shutdown_managers: HashMap::new(),
        }
    }

    /// Register a process specification.
    ///
    /// # Errors
    ///
    /// Returns an error if a process with the same name already exists.
    pub fn register(&mut self, spec: ProcessSpec) -> Result<(), SupervisorError> {
        // Check for duplicate names
        if self.specs.values().any(|s| s.name == spec.name) {
            return Err(SupervisorError::DuplicateName(spec.name));
        }

        let spec_id = spec.id;
        let instances = spec.instances;
        let restart_config = spec.restart.clone();
        let shutdown_config = spec.shutdown.clone();

        self.specs.insert(spec_id, spec.clone());

        // Create handles and managers for each instance
        for i in 0..instances {
            let handle = ProcessHandle::new(spec.clone(), i);
            self.handles.insert((spec_id, i), handle);
            self.restart_managers
                .insert((spec_id, i), RestartManager::new(restart_config.clone()));
            self.shutdown_managers
                .insert((spec_id, i), ShutdownManager::new(shutdown_config.clone()));
        }

        Ok(())
    }

    /// Unregister a process specification.
    ///
    /// # Errors
    ///
    /// Returns an error if the process is still running.
    pub fn unregister(&mut self, name: &str) -> Result<(), SupervisorError> {
        let spec_id = self
            .specs
            .values()
            .find(|s| s.name == name)
            .map(|s| s.id)
            .ok_or_else(|| SupervisorError::NotFound(name.to_string()))?;

        // Check if any instances are running
        let running = self
            .handles
            .iter()
            .filter(|((id, _), _)| *id == spec_id)
            .any(|(_, h)| h.state.is_running());

        if running {
            return Err(SupervisorError::StillRunning(name.to_string()));
        }

        // Remove all associated data
        let instances = self.specs.get(&spec_id).map_or(0, |s| s.instances);
        for i in 0..instances {
            self.handles.remove(&(spec_id, i));
            self.restart_managers.remove(&(spec_id, i));
            self.shutdown_managers.remove(&(spec_id, i));
        }
        self.specs.remove(&spec_id);

        Ok(())
    }

    /// Get a process specification by name.
    #[must_use]
    pub fn get_spec(&self, name: &str) -> Option<&ProcessSpec> {
        self.specs.values().find(|s| s.name == name)
    }

    /// Get a process handle by name and instance.
    #[must_use]
    pub fn get_handle(&self, name: &str, instance: u32) -> Option<&ProcessHandle> {
        let spec_id = self.specs.values().find(|s| s.name == name)?.id;
        self.handles.get(&(spec_id, instance))
    }

    /// Get a mutable process handle by name and instance.
    pub fn get_handle_mut(&mut self, name: &str, instance: u32) -> Option<&mut ProcessHandle> {
        let spec_id = self.specs.values().find(|s| s.name == name)?.id;
        self.handles.get_mut(&(spec_id, instance))
    }

    /// Get all handles for a process name.
    #[must_use]
    pub fn get_handles(&self, name: &str) -> Vec<&ProcessHandle> {
        let Some(spec_id) = self.specs.values().find(|s| s.name == name).map(|s| s.id) else {
            return Vec::new();
        };

        self.handles
            .iter()
            .filter(|((id, _), _)| *id == spec_id)
            .map(|(_, h)| h)
            .collect()
    }

    /// Get the restart manager for a process instance.
    pub fn get_restart_manager(
        &mut self,
        name: &str,
        instance: u32,
    ) -> Option<&mut RestartManager> {
        let spec_id = self.specs.values().find(|s| s.name == name)?.id;
        self.restart_managers.get_mut(&(spec_id, instance))
    }

    /// Get the shutdown manager for a process instance.
    pub fn get_shutdown_manager(
        &mut self,
        name: &str,
        instance: u32,
    ) -> Option<&mut ShutdownManager> {
        let spec_id = self.specs.values().find(|s| s.name == name)?.id;
        self.shutdown_managers.get_mut(&(spec_id, instance))
    }

    /// List all registered process names.
    #[must_use]
    pub fn list_names(&self) -> Vec<&str> {
        self.specs.values().map(|s| s.name.as_str()).collect()
    }

    /// Get the number of registered processes.
    #[must_use]
    pub fn process_count(&self) -> usize {
        self.specs.len()
    }

    /// Get the number of running instances.
    #[must_use]
    pub fn running_count(&self) -> usize {
        self.handles
            .values()
            .filter(|h| h.state.is_running())
            .count()
    }

    /// Get all process specifications.
    pub fn specs(&self) -> impl Iterator<Item = &ProcessSpec> {
        self.specs.values()
    }

    /// Update process state for an instance.
    pub fn update_state(&mut self, name: &str, instance: u32, state: ProcessState) {
        if let Some(handle) = self.get_handle_mut(name, instance) {
            handle.state = state;
        }
    }

    /// Update process PID for an instance.
    pub fn update_pid(&mut self, name: &str, instance: u32, pid: Option<u32>) {
        if let Some(handle) = self.get_handle_mut(name, instance) {
            handle.pid = pid;
            if pid.is_some() {
                handle.started_at = Some(chrono::Utc::now());
            }
        }
    }

    /// Increment restart count for an instance.
    pub fn increment_restart(&mut self, name: &str, instance: u32) {
        if let Some(handle) = self.get_handle_mut(name, instance) {
            handle.restart_count += 1;
            handle.last_restart = Some(chrono::Utc::now());
        }
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

/// Supervisor errors.
#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    /// Process with name already exists.
    #[error("process with name '{0}' already exists")]
    DuplicateName(String),

    /// Process not found.
    #[error("process '{0}' not found")]
    NotFound(String),

    /// Process is still running.
    #[error("process '{0}' is still running")]
    StillRunning(String),

    /// Invalid instance index.
    #[error("invalid instance index {0}")]
    InvalidInstance(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_process() {
        let mut supervisor = Supervisor::new();

        let spec = ProcessSpec::builder()
            .name("test")
            .command("echo")
            .instances(2)
            .build();

        supervisor.register(spec).unwrap();

        assert_eq!(supervisor.process_count(), 1);
        assert!(supervisor.get_spec("test").is_some());
        assert!(supervisor.get_handle("test", 0).is_some());
        assert!(supervisor.get_handle("test", 1).is_some());
    }

    #[test]
    fn test_duplicate_name_rejected() {
        let mut supervisor = Supervisor::new();

        let spec1 = ProcessSpec::builder().name("test").command("echo").build();
        let spec2 = ProcessSpec::builder().name("test").command("echo").build();

        supervisor.register(spec1).unwrap();
        let result = supervisor.register(spec2);

        assert!(matches!(result, Err(SupervisorError::DuplicateName(_))));
    }

    #[test]
    fn test_unregister_process() {
        let mut supervisor = Supervisor::new();

        let spec = ProcessSpec::builder().name("test").command("echo").build();

        supervisor.register(spec).unwrap();
        supervisor.unregister("test").unwrap();

        assert_eq!(supervisor.process_count(), 0);
        assert!(supervisor.get_spec("test").is_none());
    }

    #[test]
    fn test_running_count() {
        let mut supervisor = Supervisor::new();

        let spec = ProcessSpec::builder()
            .name("test")
            .command("echo")
            .instances(3)
            .build();

        supervisor.register(spec).unwrap();

        assert_eq!(supervisor.running_count(), 0);

        supervisor.update_state("test", 0, ProcessState::Running);
        assert_eq!(supervisor.running_count(), 1);

        supervisor.update_state("test", 1, ProcessState::Running);
        assert_eq!(supervisor.running_count(), 2);

        supervisor.update_state("test", 0, ProcessState::Stopped { exit_code: Some(0) });
        assert_eq!(supervisor.running_count(), 1);
    }
}
