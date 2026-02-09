//! Per-SHA evidence gate result cache.
//!
//! Stores gate results under `~/.apm2/private/fac/gate_cache/{sha}.yaml` so the
//! background pipeline can skip gates that `fac gates` already validated.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::types::{apm2_home_dir, now_iso8601};

/// Result of a single cached gate execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedGateResult {
    pub status: String,
    pub duration_secs: u64,
    pub completed_at: String,
}

/// Per-SHA gate cache containing results for all executed gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCache {
    pub sha: String,
    pub gates: BTreeMap<String, CachedGateResult>,
}

fn cache_dir() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("private/fac/gate_cache"))
}

fn cache_path(sha: &str) -> Result<PathBuf, String> {
    Ok(cache_dir()?.join(format!("{sha}.yaml")))
}

impl GateCache {
    /// Create a new empty cache for the given SHA.
    pub fn new(sha: &str) -> Self {
        Self {
            sha: sha.to_string(),
            gates: BTreeMap::new(),
        }
    }

    /// Load cache from disk for the given SHA. Returns `None` if not found or
    /// unparseable.
    pub fn load(sha: &str) -> Option<Self> {
        let path = cache_path(sha).ok()?;
        let content = fs::read_to_string(path).ok()?;
        let cache: Self = serde_yaml::from_str(&content).ok()?;
        if cache.sha != sha {
            return None;
        }
        Some(cache)
    }

    /// Write cache to disk.
    pub fn save(&self) -> Result<(), String> {
        let dir = cache_dir()?;
        fs::create_dir_all(&dir).map_err(|e| format!("failed to create gate cache dir: {e}"))?;
        let path = cache_path(&self.sha)?;
        let content = serde_yaml::to_string(self)
            .map_err(|e| format!("failed to serialize gate cache: {e}"))?;
        fs::write(&path, content).map_err(|e| format!("failed to write gate cache: {e}"))?;
        Ok(())
    }

    /// Look up a single gate result.
    pub fn get(&self, gate: &str) -> Option<&CachedGateResult> {
        self.gates.get(gate)
    }

    /// Record a gate result.
    pub fn set(&mut self, gate: &str, passed: bool, duration: u64) {
        self.gates.insert(
            gate.to_string(),
            CachedGateResult {
                status: if passed { "PASS" } else { "FAIL" }.to_string(),
                duration_secs: duration,
                completed_at: now_iso8601(),
            },
        );
    }

    /// Check if all recorded gates passed.
    pub fn all_passed(&self) -> bool {
        !self.gates.is_empty() && self.gates.values().all(|r| r.status == "PASS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_cache_new_is_empty() {
        let cache = GateCache::new("abc123");
        assert_eq!(cache.sha, "abc123");
        assert!(cache.gates.is_empty());
        assert!(!cache.all_passed());
    }

    #[test]
    fn test_gate_cache_set_and_get() {
        let mut cache = GateCache::new("abc123");
        cache.set("rustfmt", true, 2);
        cache.set("clippy", false, 45);

        let fmt = cache.get("rustfmt").expect("should exist");
        assert_eq!(fmt.status, "PASS");
        assert_eq!(fmt.duration_secs, 2);

        let clip = cache.get("clippy").expect("should exist");
        assert_eq!(clip.status, "FAIL");
        assert_eq!(clip.duration_secs, 45);

        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_gate_cache_all_passed() {
        let mut cache = GateCache::new("abc123");
        cache.set("rustfmt", true, 2);
        cache.set("clippy", true, 45);
        assert!(cache.all_passed());

        cache.set("test", false, 120);
        assert!(!cache.all_passed());
    }

    #[test]
    fn test_gate_cache_roundtrip_yaml() {
        let mut cache = GateCache::new("deadbeef1234567890");
        cache.set("rustfmt", true, 2);
        cache.set("clippy", true, 45);

        let yaml = serde_yaml::to_string(&cache).expect("serialize");
        let restored: GateCache = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(restored.sha, "deadbeef1234567890");
        assert_eq!(restored.gates.len(), 2);
        assert!(restored.all_passed());
    }

    #[test]
    fn test_gate_cache_load_returns_none_for_missing() {
        // Use a SHA that should never exist on disk
        assert!(GateCache::load("ffffffffffffffff_nonexistent_test_sha").is_none());
    }
}
