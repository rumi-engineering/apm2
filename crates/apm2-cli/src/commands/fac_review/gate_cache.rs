//! Per-SHA evidence gate result cache with attestation-aware reuse.
//!
//! V2 stores one file per gate under:
//! `~/.apm2/private/fac/gate_cache_v2/{sha}/{gate}.yaml`.
//! Legacy v1 (`gate_cache/{sha}.yaml`) is read as best-effort fallback.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::gate_attestation::MERGE_CONFLICT_GATE_NAME;
use super::types::{apm2_home_dir, now_iso8601};
use crate::commands::fac_permissions;

const CACHE_SCHEMA_V2: &str = "apm2.fac.gate_result_receipt.v2";
const MAX_CACHE_READ_BYTES: usize = 1_048_576;

/// Result of a single cached gate execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedGateResult {
    pub status: String,
    pub duration_secs: u64,
    pub completed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_log_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quick_mode: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GateCacheEntryV2 {
    schema: String,
    sha: String,
    gate_name: String,
    result: CachedGateResult,
}

/// Per-SHA gate cache containing results for all executed gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCache {
    pub sha: String,
    pub gates: BTreeMap<String, CachedGateResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReuseDecision {
    pub reusable: bool,
    pub reason: &'static str,
}

impl ReuseDecision {
    #[must_use]
    pub const fn hit() -> Self {
        Self {
            reusable: true,
            reason: "attestation_match",
        }
    }

    #[must_use]
    pub const fn miss(reason: &'static str) -> Self {
        Self {
            reusable: false,
            reason,
        }
    }
}

fn cache_dir_v1() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("private/fac/gate_cache"))
}

fn cache_path_v1(sha: &str) -> Result<PathBuf, String> {
    Ok(cache_dir_v1()?.join(format!("{sha}.yaml")))
}

fn cache_dir_v2() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("private/fac/gate_cache_v2"))
}

fn cache_sha_dir_v2(sha: &str) -> Result<PathBuf, String> {
    Ok(cache_dir_v2()?.join(sha))
}

fn sanitize_gate_name_for_path(gate: &str) -> String {
    gate.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn cache_gate_path_v2(sha: &str, gate: &str) -> Result<PathBuf, String> {
    let safe_gate = sanitize_gate_name_for_path(gate);
    Ok(cache_sha_dir_v2(sha)?.join(format!("{safe_gate}.yaml")))
}

fn file_is_symlink(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.file_type().is_symlink()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("failed to inspect {}: {err}", path.display())),
    }
}

fn read_bounded(path: &Path) -> Result<String, String> {
    let metadata =
        fs::metadata(path).map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if metadata.len() > MAX_CACHE_READ_BYTES as u64 {
        return Err(format!(
            "refusing oversized cache file {} ({} bytes)",
            path.display(),
            metadata.len()
        ));
    }
    fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn atomic_write(path: &Path, content: &str) -> Result<(), String> {
    if file_is_symlink(path)? {
        return Err(format!(
            "refusing to write cache via symlink path {}",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        fac_permissions::ensure_dir_with_mode(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|err| format!("failed to open {}: {err}", tmp.display()))?;
    file.write_all(content.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", tmp.display()))?;
    file.sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", tmp.display()))?;
    fs::rename(&tmp, path)
        .map_err(|err| format!("failed to atomically rename {}: {err}", path.display()))?;
    Ok(())
}

impl GateCache {
    /// Create a new empty cache for the given SHA.
    pub fn new(sha: &str) -> Self {
        Self {
            sha: sha.to_string(),
            gates: BTreeMap::new(),
        }
    }

    fn load_v2(sha: &str) -> Option<Self> {
        let dir = cache_sha_dir_v2(sha).ok()?;
        if !dir.exists() {
            return None;
        }

        let mut cache = Self::new(sha);
        let entries = fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
                continue;
            }
            if file_is_symlink(&path).ok()? {
                continue;
            }
            let content = read_bounded(&path).ok()?;
            let parsed: GateCacheEntryV2 = serde_yaml::from_str(&content).ok()?;
            if parsed.schema != CACHE_SCHEMA_V2 || parsed.sha != sha {
                continue;
            }
            cache.gates.insert(parsed.gate_name, parsed.result);
        }

        if cache.gates.is_empty() {
            None
        } else {
            Some(cache)
        }
    }

    fn load_v1(sha: &str) -> Option<Self> {
        let path = cache_path_v1(sha).ok()?;
        if !path.exists() {
            return None;
        }
        if file_is_symlink(&path).ok()? {
            return None;
        }
        let content = read_bounded(&path).ok()?;
        let cache: Self = serde_yaml::from_str(&content).ok()?;
        if cache.sha != sha {
            return None;
        }
        Some(cache)
    }

    /// Load cache from disk for the given SHA. Returns `None` if not found or
    /// unparseable.
    pub fn load(sha: &str) -> Option<Self> {
        Self::load_v2(sha).or_else(|| Self::load_v1(sha))
    }

    /// Write cache to disk using v2 per-gate files.
    pub fn save(&self) -> Result<(), String> {
        let dir = cache_sha_dir_v2(&self.sha)?;
        fac_permissions::ensure_dir_with_mode(&dir)
            .map_err(|err| format!("failed to create gate cache dir: {err}"))?;

        for (gate_name, result) in &self.gates {
            let entry = GateCacheEntryV2 {
                schema: CACHE_SCHEMA_V2.to_string(),
                sha: self.sha.clone(),
                gate_name: gate_name.clone(),
                result: result.clone(),
            };
            let content = serde_yaml::to_string(&entry)
                .map_err(|err| format!("failed to serialize gate cache entry: {err}"))?;
            let path = cache_gate_path_v2(&self.sha, gate_name)?;
            atomic_write(&path, &content)?;
        }
        Ok(())
    }

    /// Look up a single gate result.
    pub fn get(&self, gate: &str) -> Option<&CachedGateResult> {
        self.gates.get(gate)
    }

    /// Record a gate result with attestation metadata.
    pub fn set_with_attestation(
        &mut self,
        gate: &str,
        passed: bool,
        duration: u64,
        attestation_digest: Option<String>,
        quick_mode: bool,
        evidence_log_digest: Option<String>,
    ) {
        self.gates.insert(
            gate.to_string(),
            CachedGateResult {
                status: if passed { "PASS" } else { "FAIL" }.to_string(),
                duration_secs: duration,
                completed_at: now_iso8601(),
                attestation_digest,
                evidence_log_digest,
                quick_mode: Some(quick_mode),
            },
        );
    }

    /// Evaluate whether a cached gate result is safe to reuse.
    ///
    /// `require_full_mode` should be true for normal push pipeline runs.
    pub fn check_reuse(
        &self,
        gate: &str,
        expected_attestation_digest: Option<&str>,
        require_full_mode: bool,
    ) -> ReuseDecision {
        if gate == MERGE_CONFLICT_GATE_NAME {
            return ReuseDecision::miss("policy_merge_conflict_recompute");
        }

        let Some(cached) = self.get(gate) else {
            return ReuseDecision::miss("no_record");
        };
        if cached.status != "PASS" {
            return ReuseDecision::miss("status_not_pass");
        }
        if require_full_mode && cached.quick_mode.unwrap_or(false) {
            return ReuseDecision::miss("quick_receipt_not_reusable");
        }
        let Some(expected_digest) = expected_attestation_digest else {
            return ReuseDecision::miss("attestation_missing_current");
        };
        if cached.attestation_digest.as_deref() != Some(expected_digest) {
            return ReuseDecision::miss("attestation_mismatch");
        }
        if cached
            .evidence_log_digest
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return ReuseDecision::miss("evidence_digest_missing");
        }
        ReuseDecision::hit()
    }
}

#[cfg(test)]
mod tests {
    use super::{GateCache, ReuseDecision};

    #[test]
    fn test_gate_cache_new_is_empty() {
        let cache = GateCache::new("abc123");
        assert_eq!(cache.sha, "abc123");
        assert!(cache.gates.is_empty());
        assert!(cache.gates.values().all(|result| result.status == "PASS"));
    }

    #[test]
    fn test_gate_cache_set_and_get() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            2,
            Some("digest-a".to_string()),
            false,
            Some("log-a".to_string()),
        );
        cache.set_with_attestation(
            "clippy",
            false,
            45,
            Some("digest-b".to_string()),
            false,
            Some("log-b".to_string()),
        );

        let fmt = cache.get("rustfmt").expect("should exist");
        assert_eq!(fmt.status, "PASS");
        assert_eq!(fmt.duration_secs, 2);
        assert_eq!(fmt.attestation_digest.as_deref(), Some("digest-a"));

        let clip = cache.get("clippy").expect("should exist");
        assert_eq!(clip.status, "FAIL");
        assert_eq!(clip.duration_secs, 45);

        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_gate_cache_pass_status_evaluates_as_expected() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            2,
            Some("digest-a".to_string()),
            false,
            Some("log-a".to_string()),
        );
        cache.set_with_attestation(
            "clippy",
            true,
            45,
            Some("digest-b".to_string()),
            false,
            Some("log-b".to_string()),
        );
        assert!(cache.gates.values().all(|result| result.status == "PASS"));

        cache.set_with_attestation(
            "test",
            false,
            120,
            Some("digest-c".to_string()),
            false,
            Some("log-c".to_string()),
        );
        assert!(cache.gates.values().any(|result| result.status != "PASS"));
    }

    #[test]
    fn test_gate_cache_roundtrip_yaml() {
        let mut cache = GateCache::new("deadbeef1234567890");
        cache.set_with_attestation(
            "rustfmt",
            true,
            2,
            Some("digest-a".to_string()),
            false,
            Some("log-a".to_string()),
        );
        cache.set_with_attestation(
            "clippy",
            true,
            45,
            Some("digest-b".to_string()),
            false,
            Some("log-b".to_string()),
        );

        let yaml = serde_yaml::to_string(&cache).expect("serialize");
        let restored: GateCache = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(restored.sha, "deadbeef1234567890");
        assert_eq!(restored.gates.len(), 2);
        assert!(
            restored
                .gates
                .values()
                .all(|result| result.status == "PASS")
        );
    }

    #[test]
    fn test_gate_cache_load_returns_none_for_missing() {
        assert!(GateCache::load("ffffffffffffffff_nonexistent_test_sha").is_none());
    }

    #[test]
    fn test_reuse_decision_requires_attestation_and_log_digest() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("digest-1".to_string()),
            false,
            Some("log-digest".to_string()),
        );
        assert_eq!(
            cache.check_reuse("rustfmt", Some("digest-1"), true),
            ReuseDecision::hit()
        );
        assert_eq!(
            cache.check_reuse("rustfmt", Some("digest-2"), true).reason,
            "attestation_mismatch"
        );
        assert_eq!(
            cache
                .check_reuse("merge_conflict_main", Some("digest-1"), true)
                .reason,
            "policy_merge_conflict_recompute"
        );
    }
}
