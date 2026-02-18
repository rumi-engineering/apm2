//! Shared job-payload contract for queued FAC `gates` jobs.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Schema identifier for the `source.patch` payload in `kind="gates"` jobs.
pub(super) const GATES_JOB_OPTIONS_SCHEMA: &str = "apm2.fac.gates_job_options.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GatesJobOptionsV1 {
    pub schema: String,
    pub force: bool,
    pub quick: bool,
    pub timeout_seconds: u64,
    pub memory_max: String,
    pub pids_max: u64,
    pub cpu_quota: String,
    pub gate_profile: String,
    pub workspace_root: String,
    /// TCK-00540: Allow reuse of legacy gate cache entries without
    /// RFC-0028/0029 receipt bindings (unsafe migration override).
    /// Defaults to `false` (fail-closed) for backward compatibility with
    /// payloads that pre-date TCK-00540.
    #[serde(default)]
    pub allow_legacy_cache: bool,
}

impl GatesJobOptionsV1 {
    #[cfg_attr(test, allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        force: bool,
        quick: bool,
        timeout_seconds: u64,
        memory_max: &str,
        pids_max: u64,
        cpu_quota: &str,
        gate_profile: &str,
        workspace_root: &Path,
        allow_legacy_cache: bool,
    ) -> Self {
        Self {
            schema: GATES_JOB_OPTIONS_SCHEMA.to_string(),
            force,
            quick,
            timeout_seconds,
            memory_max: memory_max.to_string(),
            pids_max,
            cpu_quota: cpu_quota.to_string(),
            gate_profile: gate_profile.to_string(),
            workspace_root: workspace_root.to_string_lossy().to_string(),
            allow_legacy_cache,
        }
    }
}
