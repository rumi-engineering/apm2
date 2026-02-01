#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! State persistence module.
//!
//! Handles saving and restoring process manager state for recovery after
//! restarts.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::process::{ProcessId, ProcessSpec, ProcessState};

/// Persisted state for the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    /// Version of the state format.
    pub version: u32,

    /// Time when state was saved.
    pub saved_at: DateTime<Utc>,

    /// Daemon start time.
    pub daemon_started_at: DateTime<Utc>,

    /// Process specifications.
    pub specs: HashMap<ProcessId, ProcessSpec>,

    /// Process instance states.
    pub instances: Vec<PersistedProcessInstance>,
}

impl PersistedState {
    /// Current state format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new empty persisted state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            saved_at: Utc::now(),
            daemon_started_at: Utc::now(),
            specs: HashMap::new(),
            instances: Vec::new(),
        }
    }

    /// Load state from a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load(path: &std::path::Path) -> Result<Self, StateError> {
        let content = std::fs::read_to_string(path).map_err(StateError::Io)?;
        let state: Self = serde_json::from_str(&content).map_err(StateError::Parse)?;

        if state.version > Self::CURRENT_VERSION {
            return Err(StateError::UnsupportedVersion(state.version));
        }

        Ok(state)
    }

    /// Save state to a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&mut self, path: &std::path::Path) -> Result<(), StateError> {
        self.saved_at = Utc::now();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(StateError::Io)?;
        }

        // Write to temp file first, then rename (atomic)
        let temp_path = path.with_extension("tmp");
        let content = serde_json::to_string_pretty(self).map_err(StateError::Serialize)?;
        std::fs::write(&temp_path, content).map_err(StateError::Io)?;
        std::fs::rename(&temp_path, path).map_err(StateError::Io)?;

        Ok(())
    }

    /// Add a process specification.
    pub fn add_spec(&mut self, spec: ProcessSpec) {
        self.specs.insert(spec.id, spec);
    }

    /// Remove a process specification.
    pub fn remove_spec(&mut self, id: &ProcessId) {
        self.specs.remove(id);
        self.instances.retain(|i| i.spec_id != *id);
    }

    /// Update instance state.
    pub fn update_instance(&mut self, instance: PersistedProcessInstance) {
        if let Some(existing) = self
            .instances
            .iter_mut()
            .find(|i| i.spec_id == instance.spec_id && i.instance_index == instance.instance_index)
        {
            *existing = instance;
        } else {
            self.instances.push(instance);
        }
    }
}

impl Default for PersistedState {
    fn default() -> Self {
        Self::new()
    }
}

/// Persisted state for a single process instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedProcessInstance {
    /// Process specification ID.
    pub spec_id: ProcessId,

    /// Instance index.
    pub instance_index: u32,

    /// Process state.
    pub state: ProcessState,

    /// OS process ID (if running).
    pub pid: Option<u32>,

    /// Time when started.
    pub started_at: Option<DateTime<Utc>>,

    /// Number of restarts.
    pub restart_count: u32,

    /// Last restart time.
    pub last_restart: Option<DateTime<Utc>>,

    /// Bound credential profile ID.
    pub credential_profile: Option<String>,
}

impl PersistedProcessInstance {
    /// Create a new persisted process instance.
    #[must_use]
    pub const fn new(spec_id: ProcessId, instance_index: u32) -> Self {
        Self {
            spec_id,
            instance_index,
            state: ProcessState::Stopped { exit_code: None },
            pid: None,
            started_at: None,
            restart_count: 0,
            last_restart: None,
            credential_profile: None,
        }
    }
}

/// State manager that handles periodic persistence.
#[derive(Debug)]
pub struct StateManager {
    /// Path to state file.
    path: PathBuf,

    /// Current state.
    state: PersistedState,

    /// Whether state has unsaved changes.
    dirty: bool,
}

impl StateManager {
    /// Create a new state manager.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: PersistedState::new(),
            dirty: false,
        }
    }

    /// Load existing state from disk, or create new if not found.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file exists but cannot be read.
    pub fn load_or_create(&mut self) -> Result<(), StateError> {
        if self.path.exists() {
            self.state = PersistedState::load(&self.path)?;
        } else {
            self.state = PersistedState::new();
            self.dirty = true;
        }
        Ok(())
    }

    /// Get a reference to the current state.
    #[must_use]
    pub const fn state(&self) -> &PersistedState {
        &self.state
    }

    /// Get a mutable reference to the current state.
    pub const fn state_mut(&mut self) -> &mut PersistedState {
        self.dirty = true;
        &mut self.state
    }

    /// Save state if dirty.
    ///
    /// # Errors
    ///
    /// Returns an error if the state cannot be saved.
    pub fn save_if_dirty(&mut self) -> Result<(), StateError> {
        if self.dirty {
            self.state.save(&self.path)?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Force save state.
    ///
    /// # Errors
    ///
    /// Returns an error if the state cannot be saved.
    pub fn save(&mut self) -> Result<(), StateError> {
        self.state.save(&self.path)?;
        self.dirty = false;
        Ok(())
    }

    /// Mark state as dirty (needs saving).
    pub const fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Check if state is dirty.
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }
}

/// State persistence errors.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parse error.
    #[error("failed to parse state: {0}")]
    Parse(#[from] serde_json::Error),

    /// JSON serialize error.
    #[error("failed to serialize state: {0}")]
    Serialize(serde_json::Error),

    /// Unsupported state version.
    #[error("unsupported state version: {0}")]
    UnsupportedVersion(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persisted_state_roundtrip() {
        let mut state = PersistedState::new();

        let spec = ProcessSpec::builder().name("test").command("echo").build();
        let spec_id = spec.id;
        state.add_spec(spec);

        let instance = PersistedProcessInstance {
            spec_id,
            instance_index: 0,
            state: ProcessState::Running,
            pid: Some(12345),
            started_at: Some(Utc::now()),
            restart_count: 2,
            last_restart: None,
            credential_profile: Some("claude-work".to_string()),
        };
        state.update_instance(instance);

        // Serialize and deserialize
        let json = serde_json::to_string(&state).unwrap();
        let loaded: PersistedState = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.specs.len(), 1);
        assert_eq!(loaded.instances.len(), 1);
        assert_eq!(loaded.instances[0].pid, Some(12345));
    }

    use crate::process::ProcessSpec;
}
