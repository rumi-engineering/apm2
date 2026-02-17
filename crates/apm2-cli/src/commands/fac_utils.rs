// AGENT-AUTHORED (TCK-00535)
//! Shared utilities for FAC commands.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use apm2_core::fac::job_spec::{FacJobSpecV1, MAX_JOB_SPEC_SIZE};
use apm2_core::github::resolve_apm2_home;

/// Queue subdirectory under `$APM2_HOME`.
pub const QUEUE_DIR: &str = "queue";

/// Maximum number of directory entries to scan per directory.
/// Prevents unbounded memory growth (INV-QSTAT-001).
pub const MAX_SCAN_ENTRIES: usize = 4096;

/// Resolves the queue root directory from `$APM2_HOME/queue`.
pub fn resolve_queue_root() -> Result<PathBuf, String> {
    let home = resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home".to_string())?;
    Ok(home.join(QUEUE_DIR))
}

/// Resolves the FAC root directory at `$APM2_HOME/private/fac`.
pub fn resolve_fac_root() -> Result<PathBuf, String> {
    let home = resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home".to_string())?;
    Ok(home.join("private").join("fac"))
}

/// Reads and deserializes a job spec from a file with bounded I/O.
///
/// Uses `File::open().take(MAX_JOB_SPEC_SIZE + 1)` to enforce the size
/// limit on the actual read operation. Prevents denial-of-service via
/// special files (INV-QSTAT-002).
pub fn read_job_spec_bounded(path: &Path) -> Result<FacJobSpecV1, String> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // Read at most MAX_JOB_SPEC_SIZE + 1 bytes.  If we get more than
    // MAX_JOB_SPEC_SIZE, the file is over the limit.
    let limit = (MAX_JOB_SPEC_SIZE as u64).saturating_add(1);
    let mut bounded_reader = file.take(limit);
    let mut bytes = Vec::with_capacity(MAX_JOB_SPEC_SIZE.min(8192));
    bounded_reader
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() > MAX_JOB_SPEC_SIZE {
        return Err(format!(
            "file content {} exceeds max {}",
            bytes.len(),
            MAX_JOB_SPEC_SIZE
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}
