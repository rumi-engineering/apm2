//! Per-SHA evidence gate result cache with attestation-aware reuse.
//!
//! V2 stores one file per gate under:
//! `~/.apm2/private/fac/gate_cache_v2/{sha}/{gate}.yaml`.
//! Legacy v1 (`gate_cache/{sha}.yaml`) is read as best-effort fallback.
//!
//! # Signed Receipts (TCK-00576)
//!
//! Each `CachedGateResult` carries an optional Ed25519 signature over the
//! canonical bytes of the receipt entry (domain-separated with
//! `GATE_CACHE_RECEIPT:`).  In default mode, `check_reuse` requires a
//! valid signature — unsigned or forged entries are rejected for cache
//! reuse (fail-closed).
//!
//! # Legacy Cache Reuse Policy (TCK-00540)
//!
//! Gate cache entries are treated as **untrusted** unless they carry
//! RFC-0028 authorization and RFC-0029 admission receipt bindings
//! (`rfc0028_receipt_bound` and `rfc0029_receipt_bound` fields).
//!
//! In default mode, `check_reuse` rejects entries missing these bindings
//! (fail-closed). The `--allow-legacy-cache` CLI flag sets
//! `allow_legacy_cache = true` to permit fallback reuse of unbound entries,
//! and marks the reuse decision accordingly.
//!
//! Migration path: as gates are re-run, new entries will carry bound
//! receipts. Over time, all cache entries become bound and the override
//! becomes unnecessary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use apm2_core::crypto::{Signer, VerifyingKey};
use apm2_core::fac::{GATE_CACHE_RECEIPT_PREFIX, sign_with_domain, verify_with_domain};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use super::gate_attestation::MERGE_CONFLICT_GATE_NAME;
use super::types::{apm2_home_dir, now_iso8601};
use crate::commands::fac_permissions;

const CACHE_SCHEMA_V2: &str = "apm2.fac.gate_result_receipt.v2";
const MAX_CACHE_READ_BYTES: usize = 1_048_576;

/// Maximum length of `signature_hex` and `signer_id` fields (TCK-00576).
/// Ed25519 signature = 64 bytes = 128 hex chars; public key = 32 bytes = 64
/// hex chars.  256 is generous but bounded.
const MAX_SIG_FIELD_LENGTH: usize = 256;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub was_truncated: Option<bool>,
    /// Absolute path to the evidence log file produced during this gate run.
    /// SHA-bound: ensures tool-output selectors resolve to the exact log for
    /// the requested SHA rather than the latest file by mtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    /// Hex-encoded Ed25519 signature over the canonical bytes of this entry
    /// (TCK-00576).  Domain-separated with `GATE_CACHE_RECEIPT:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Hex-encoded Ed25519 public key of the signer (TCK-00576).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,
    /// Whether this cache entry is bound to an RFC-0028 authorization receipt
    /// (TCK-00540). Legacy entries without this field default to `false`
    /// (untrusted).
    #[serde(default)]
    pub rfc0028_receipt_bound: bool,
    /// Whether this cache entry is bound to an RFC-0029 admission receipt
    /// (TCK-00540). Legacy entries without this field default to `false`
    /// (untrusted).
    #[serde(default)]
    pub rfc0029_receipt_bound: bool,
    /// When `true`, this cache entry was reused via the `--allow-legacy-cache`
    /// unsafe override despite missing RFC-0028/0029 receipt bindings
    /// (TCK-00540). Receipts are marked accordingly for audit.
    #[serde(default)]
    pub legacy_cache_override: bool,
}

impl CachedGateResult {
    /// Returns deterministic canonical bytes for signing.
    ///
    /// Includes all fields that are semantically meaningful for cache reuse
    /// decisions.  `signature_hex` and `signer_id` are excluded (they are
    /// the authentication envelope, not the authenticated content).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn canonical_bytes(&self, sha: &str, gate_name: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        // SHA binding
        buf.extend_from_slice(&(sha.len() as u32).to_be_bytes());
        buf.extend_from_slice(sha.as_bytes());

        // Gate name binding
        buf.extend_from_slice(&(gate_name.len() as u32).to_be_bytes());
        buf.extend_from_slice(gate_name.as_bytes());

        // Status
        buf.extend_from_slice(&(self.status.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.status.as_bytes());

        // Duration
        buf.extend_from_slice(&self.duration_secs.to_be_bytes());

        // Completed at
        buf.extend_from_slice(&(self.completed_at.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.completed_at.as_bytes());

        // Attestation digest
        Self::append_optional_string(&mut buf, self.attestation_digest.as_deref());

        // Evidence log digest
        Self::append_optional_string(&mut buf, self.evidence_log_digest.as_deref());

        // Quick mode
        match self.quick_mode {
            Some(true) => buf.push(2u8),
            Some(false) => buf.push(1u8),
            None => buf.push(0u8),
        }

        // Log bundle hash
        Self::append_optional_string(&mut buf, self.log_bundle_hash.as_deref());

        // bytes_written
        Self::append_optional_u64(&mut buf, self.bytes_written);

        // bytes_total
        Self::append_optional_u64(&mut buf, self.bytes_total);

        // was_truncated
        match self.was_truncated {
            Some(true) => buf.push(2u8),
            Some(false) => buf.push(1u8),
            None => buf.push(0u8),
        }

        // log_path
        Self::append_optional_string(&mut buf, self.log_path.as_deref());

        // TCK-00540: RFC-0028/0029 receipt binding fields
        buf.push(u8::from(self.rfc0028_receipt_bound));
        buf.push(u8::from(self.rfc0029_receipt_bound));
        buf.push(u8::from(self.legacy_cache_override));

        buf
    }

    #[allow(clippy::cast_possible_truncation)]
    fn append_optional_string(buf: &mut Vec<u8>, value: Option<&str>) {
        if let Some(s) = value {
            buf.push(1u8);
            buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
        } else {
            buf.push(0u8);
        }
    }

    fn append_optional_u64(buf: &mut Vec<u8>, value: Option<u64>) {
        if let Some(v) = value {
            buf.push(1u8);
            buf.extend_from_slice(&v.to_be_bytes());
        } else {
            buf.push(0u8);
        }
    }

    /// Sign this entry using the given signer and context.
    ///
    /// Populates `signature_hex` and `signer_id` fields in-place.
    pub fn sign(&mut self, signer: &Signer, sha: &str, gate_name: &str) {
        let canonical = self.canonical_bytes(sha, gate_name);
        let sig = sign_with_domain(signer, GATE_CACHE_RECEIPT_PREFIX, &canonical);
        self.signature_hex = Some(hex::encode(sig.to_bytes()));
        self.signer_id = Some(hex::encode(signer.verifying_key().to_bytes()));
    }

    /// Verify the signature on this entry against the expected verifying key.
    ///
    /// Returns `Ok(())` if the signature is valid and matches the expected
    /// key.  Returns `Err` with a human-readable reason on any failure.
    pub fn verify(
        &self,
        expected_key: &VerifyingKey,
        sha: &str,
        gate_name: &str,
    ) -> Result<(), String> {
        let sig_hex = self
            .signature_hex
            .as_deref()
            .ok_or("missing signature_hex")?;
        let signer_hex = self.signer_id.as_deref().ok_or("missing signer_id")?;

        // Bound field lengths to prevent memory exhaustion on crafted input.
        if sig_hex.len() > MAX_SIG_FIELD_LENGTH {
            return Err("signature_hex exceeds maximum length".to_string());
        }
        if signer_hex.len() > MAX_SIG_FIELD_LENGTH {
            return Err("signer_id exceeds maximum length".to_string());
        }

        // Verify signer_id matches expected key (constant-time comparison
        // on the raw bytes after decode).
        let signer_bytes =
            hex::decode(signer_hex).map_err(|e| format!("invalid signer_id hex: {e}"))?;
        let expected_bytes = expected_key.to_bytes();
        if signer_bytes.len() != expected_bytes.len() {
            return Err("signer_id length mismatch".to_string());
        }
        // Constant-time comparison to prevent timing side channels.
        let eq: bool =
            subtle::ConstantTimeEq::ct_eq(signer_bytes.as_slice(), expected_bytes.as_slice())
                .into();
        if !eq {
            return Err("signer_id does not match expected verifying key".to_string());
        }

        // Decode and verify signature.
        let sig_bytes =
            hex::decode(sig_hex).map_err(|e| format!("invalid signature_hex hex: {e}"))?;
        let signature = apm2_core::crypto::parse_signature(&sig_bytes)
            .map_err(|e| format!("malformed signature: {e}"))?;

        let canonical = self.canonical_bytes(sha, gate_name);
        verify_with_domain(
            expected_key,
            GATE_CACHE_RECEIPT_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|_| "signature verification failed".to_string())
    }
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

fn cache_lock_dir_v2() -> Result<PathBuf, String> {
    Ok(cache_dir_v2()?.join(".locks"))
}

fn cache_lock_path_v2(sha: &str) -> Result<PathBuf, String> {
    Ok(cache_lock_dir_v2()?.join(format!("{sha}.lock")))
}

fn acquire_sha_lock(sha: &str, exclusive: bool) -> Result<std::fs::File, String> {
    let lock_path = cache_lock_path_v2(sha)?;
    let lock_parent = lock_path
        .parent()
        .ok_or_else(|| format!("lock path has no parent: {}", lock_path.display()))?;
    fac_permissions::ensure_dir_with_mode(lock_parent)
        .map_err(|err| format!("failed to create gate cache lock dir: {err}"))?;
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open gate cache lock {}: {err}",
                lock_path.display()
            )
        })?;
    if exclusive {
        FileExt::lock_exclusive(&lock_file).map_err(|err| {
            format!(
                "failed to acquire exclusive gate cache lock {}: {err}",
                lock_path.display()
            )
        })?;
    } else {
        FileExt::lock_shared(&lock_file).map_err(|err| {
            format!(
                "failed to acquire shared gate cache lock {}: {err}",
                lock_path.display()
            )
        })?;
    }
    Ok(lock_file)
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
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "refusing to read non-file cache path {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_CACHE_READ_BYTES as u64 {
        return Err(format!(
            "refusing oversized cache file {} ({} bytes)",
            path.display(),
            metadata.len()
        ));
    }
    let mut file = file;
    let mut limited = (&mut file).take(MAX_CACHE_READ_BYTES as u64 + 1);
    let mut content = String::new();
    limited
        .read_to_string(&mut content)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    if limited.limit() == 0 {
        return Err(format!(
            "refusing oversized cache file {} (> {} bytes)",
            path.display(),
            MAX_CACHE_READ_BYTES
        ));
    }
    Ok(content)
}

impl GateCache {
    /// Create a new empty cache for the given SHA.
    pub fn new(sha: &str) -> Self {
        Self {
            sha: sha.to_string(),
            gates: BTreeMap::new(),
        }
    }

    fn load_v2_unlocked(sha: &str) -> Option<Self> {
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

    fn load_v1_unlocked(sha: &str) -> Option<Self> {
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
        let _lock = acquire_sha_lock(sha, false).ok()?;
        Self::load_v2_unlocked(sha).or_else(|| Self::load_v1_unlocked(sha))
    }

    /// Write cache to disk using v2 per-gate files.
    pub fn save(&self) -> Result<(), String> {
        let _lock = acquire_sha_lock(&self.sha, true)?;
        let dir = cache_sha_dir_v2(&self.sha)?;
        fac_permissions::ensure_dir_with_mode(&dir)
            .map_err(|err| format!("failed to create gate cache dir: {err}"))?;

        let mut expected_paths = BTreeSet::new();
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
            expected_paths.insert(path.clone());
            fac_permissions::write_fac_file_with_mode(path.as_path(), content.as_bytes())
                .map_err(|err| format!("failed to write cache entry {}: {err}", path.display()))?;
        }

        // Remove stale per-gate cache files so push never projects stale extras.
        let entries = fs::read_dir(&dir)
            .map_err(|err| format!("failed to list gate cache dir {}: {err}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|err| {
                format!(
                    "failed to read gate cache dir entry in {}: {err}",
                    dir.display()
                )
            })?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
                continue;
            }
            if expected_paths.contains(&path) {
                continue;
            }
            if file_is_symlink(&path)? {
                return Err(format!(
                    "refusing to remove symlinked gate cache entry {}",
                    path.display()
                ));
            }
            fs::remove_file(&path).map_err(|err| {
                format!(
                    "failed to remove stale gate cache entry {}: {err}",
                    path.display()
                )
            })?;
        }
        Ok(())
    }

    /// Sign all gate entries in this cache with the given signer (TCK-00576).
    pub fn sign_all(&mut self, signer: &Signer) {
        let sha = self.sha.clone();
        for (gate_name, result) in &mut self.gates {
            result.sign(signer, &sha, gate_name);
        }
    }

    /// Look up a single gate result.
    pub fn get(&self, gate: &str) -> Option<&CachedGateResult> {
        self.gates.get(gate)
    }

    /// Record a gate result with attestation metadata.
    ///
    /// New entries created by the current pipeline carry RFC-0028/0029
    /// receipt bindings (`rfc0028_receipt_bound = true`,
    /// `rfc0029_receipt_bound = true`). Legacy entries loaded from disk
    /// may have these fields as `false`.
    #[allow(clippy::too_many_arguments)]
    pub fn set_with_attestation(
        &mut self,
        gate: &str,
        passed: bool,
        duration: u64,
        attestation_digest: Option<String>,
        quick_mode: bool,
        evidence_log_digest: Option<String>,
        log_path: Option<String>,
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
                log_bundle_hash: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_path,
                signature_hex: None,
                signer_id: None,
                // TCK-00540: new entries carry receipt bindings by default.
                rfc0028_receipt_bound: true,
                rfc0029_receipt_bound: true,
                legacy_cache_override: false,
            },
        );
    }

    /// Downgrade a cache entry to reflect that it was reused via the
    /// `--allow-legacy-cache` unsafe override (TCK-00540 fix round 2).
    ///
    /// When a cache hit occurs through `legacy_cache_override_unsafe`,
    /// `set_with_attestation` initially writes the entry with default
    /// bindings (`rfc0028_receipt_bound=true`, `rfc0029_receipt_bound=true`,
    /// `legacy_cache_override=false`).  This method corrects the entry to
    /// preserve the override audit trail:
    ///
    /// - `rfc0028_receipt_bound = false`
    /// - `rfc0029_receipt_bound = false`
    /// - `legacy_cache_override = true`
    ///
    /// This ensures that future default-mode runs (without
    /// `--allow-legacy-cache`) will still detect and deny the entry until
    /// it has been legitimately re-attested with actual RFC-0028/0029
    /// receipts.
    pub fn mark_legacy_override(&mut self, gate: &str) {
        if let Some(entry) = self.gates.get_mut(gate) {
            entry.rfc0028_receipt_bound = false;
            entry.rfc0029_receipt_bound = false;
            entry.legacy_cache_override = true;
        }
    }

    /// Backfill truncation and log-bundle metadata from evidence gate results.
    ///
    /// Called after all gates have run and `attach_log_bundle_hash` has
    /// populated per-result `log_bundle_hash` values.  Updates existing
    /// cache entries in-place so the durable receipt carries the same
    /// metadata as the in-memory `EvidenceGateResult`.
    pub fn backfill_evidence_metadata(
        &mut self,
        gate_name: &str,
        log_bundle_hash: Option<&str>,
        bytes_written: Option<u64>,
        bytes_total: Option<u64>,
        was_truncated: Option<bool>,
        log_path: Option<&str>,
    ) {
        if let Some(entry) = self.gates.get_mut(gate_name) {
            if log_bundle_hash.is_some() {
                entry.log_bundle_hash = log_bundle_hash.map(str::to_string);
            }
            if bytes_written.is_some() {
                entry.bytes_written = bytes_written;
            }
            if bytes_total.is_some() {
                entry.bytes_total = bytes_total;
            }
            if was_truncated.is_some() {
                entry.was_truncated = was_truncated;
            }
            if log_path.is_some() {
                entry.log_path = log_path.map(str::to_string);
            }
        }
    }

    /// Evaluate whether a cached gate result is safe to reuse.
    ///
    /// In default mode, signature verification is mandatory: unsigned or
    /// forged receipts are rejected (fail-closed, TCK-00576).
    ///
    /// `verifying_key` is the expected signer's public key.  Pass `None`
    /// to skip signature verification (developer/test mode only).
    ///
    /// `require_full_mode` should be true for normal push pipeline runs.
    ///
    /// `allow_legacy_cache` when `true` permits reuse of cache entries
    /// that lack RFC-0028/0029 receipt bindings (unsafe override,
    /// TCK-00540). In default mode (`false`), entries without both
    /// `rfc0028_receipt_bound` and `rfc0029_receipt_bound` are rejected
    /// (fail-closed).
    pub fn check_reuse(
        &self,
        gate: &str,
        expected_attestation_digest: Option<&str>,
        require_full_mode: bool,
        verifying_key: Option<&VerifyingKey>,
        allow_legacy_cache: bool,
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

        // TCK-00576: Signature verification gate (fail-closed in default mode).
        if let Some(key) = verifying_key {
            if let Err(_reason) = cached.verify(key, &self.sha, gate) {
                return ReuseDecision::miss("signature_invalid");
            }
        } else {
            // No verifying key provided: unsigned receipts cannot be reused
            // in any mode.  Fail closed.
            if cached.signature_hex.is_none() {
                return ReuseDecision::miss("signature_missing");
            }
        }

        // TCK-00540: RFC-0028/0029 receipt binding gate (fail-closed by
        // default). Cache entries without both receipt bindings are treated
        // as untrusted legacy entries. The `--allow-legacy-cache` flag
        // permits unsafe override for migration.
        if !cached.rfc0028_receipt_bound || !cached.rfc0029_receipt_bound {
            if allow_legacy_cache {
                return ReuseDecision {
                    reusable: true,
                    reason: "legacy_cache_override_unsafe",
                };
            }
            return ReuseDecision::miss("receipt_binding_missing");
        }

        ReuseDecision::hit()
    }

    /// Verify a specific gate receipt against the expected verifying key.
    ///
    /// Returns `Ok(())` on success or `Err(reason)` on failure.
    /// Used by the `apm2 fac receipts verify` CLI command.
    #[allow(dead_code)]
    pub fn verify_gate(&self, gate: &str, verifying_key: &VerifyingKey) -> Result<(), String> {
        let cached = self
            .get(gate)
            .ok_or_else(|| format!("no cached result for gate '{gate}'"))?;
        cached.verify(verifying_key, &self.sha, gate)
    }
}

#[cfg(test)]
mod tests {
    use apm2_core::crypto::Signer;

    use super::{GateCache, ReuseDecision};

    fn make_signed_cache(signer: &Signer) -> GateCache {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("digest-1".to_string()),
            false,
            Some("log-digest".to_string()),
            None,
        );
        cache.sign_all(signer);
        cache
    }

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
            None,
        );
        cache.set_with_attestation(
            "clippy",
            false,
            45,
            Some("digest-b".to_string()),
            false,
            Some("log-b".to_string()),
            None,
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
            None,
        );
        cache.set_with_attestation(
            "clippy",
            true,
            45,
            Some("digest-b".to_string()),
            false,
            Some("log-b".to_string()),
            None,
        );
        assert!(cache.gates.values().all(|result| result.status == "PASS"));

        cache.set_with_attestation(
            "test",
            false,
            120,
            Some("digest-c".to_string()),
            false,
            Some("log-c".to_string()),
            None,
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
            Some("/tmp/rustfmt.log".to_string()),
        );
        cache.set_with_attestation(
            "clippy",
            true,
            45,
            Some("digest-b".to_string()),
            false,
            Some("log-b".to_string()),
            Some("/tmp/clippy.log".to_string()),
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
        let signer = Signer::generate();
        let cache = make_signed_cache(&signer);
        let vk = signer.verifying_key();
        assert_eq!(
            cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false),
            ReuseDecision::hit()
        );
        assert_eq!(
            cache
                .check_reuse("rustfmt", Some("digest-2"), true, Some(&vk), false)
                .reason,
            "attestation_mismatch"
        );
        assert_eq!(
            cache
                .check_reuse(
                    "merge_conflict_main",
                    Some("digest-1"),
                    true,
                    Some(&vk),
                    false
                )
                .reason,
            "policy_merge_conflict_recompute"
        );
    }

    // --- TCK-00576: Signed receipt verification tests ---

    /// Signed receipt passes verification with the correct key.
    #[test]
    fn signed_receipt_valid_reuse() {
        let signer = Signer::generate();
        let cache = make_signed_cache(&signer);
        let vk = signer.verifying_key();
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(reuse.reusable, "validly signed receipt must be reusable");
        assert_eq!(reuse.reason, "attestation_match");
    }

    /// Unsigned receipt is rejected for cache reuse (fail-closed).
    #[test]
    fn unsigned_receipt_rejected_for_reuse() {
        let signer = Signer::generate();
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("digest-1".to_string()),
            false,
            Some("log-digest".to_string()),
            None,
        );
        // Do NOT sign the cache.
        let vk = signer.verifying_key();
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(!reuse.reusable, "unsigned receipt must NOT be reusable");
        assert_eq!(reuse.reason, "signature_invalid");
    }

    /// Receipt signed with wrong key is rejected (forged receipt).
    #[test]
    fn forged_receipt_wrong_key_rejected() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let cache = make_signed_cache(&signer_a);
        let vk_b = signer_b.verifying_key();
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk_b), false);
        assert!(
            !reuse.reusable,
            "receipt signed with wrong key must NOT be reusable"
        );
        assert_eq!(reuse.reason, "signature_invalid");
    }

    /// Receipt with tampered payload is rejected.
    #[test]
    fn tampered_receipt_rejected() {
        let signer = Signer::generate();
        let mut cache = make_signed_cache(&signer);

        // Tamper with the attestation digest after signing.
        if let Some(entry) = cache.gates.get_mut("rustfmt") {
            entry.attestation_digest = Some("tampered-digest".to_string());
        }

        let vk = signer.verifying_key();
        // The attestation_digest now mismatches what check_reuse expects,
        // so it will fail on attestation_mismatch first.
        let reuse = cache.check_reuse("rustfmt", Some("tampered-digest"), true, Some(&vk), false);
        assert!(!reuse.reusable, "tampered receipt must NOT be reusable");
        // The signature was computed over original data; tampered data
        // produces a different canonical_bytes, so signature fails.
        assert_eq!(reuse.reason, "signature_invalid");
    }

    /// When no verifying key is provided, unsigned entries fail closed.
    #[test]
    fn no_verifying_key_unsigned_entry_fails_closed() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("digest-1".to_string()),
            false,
            Some("log-digest".to_string()),
            None,
        );
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, None, false);
        assert!(
            !reuse.reusable,
            "unsigned receipt without verifying key must fail closed"
        );
        assert_eq!(reuse.reason, "signature_missing");
    }

    /// Verify roundtrip: sign, serialize to YAML, deserialize, verify.
    #[test]
    fn sign_serialize_deserialize_verify_roundtrip() {
        let signer = Signer::generate();
        let cache = make_signed_cache(&signer);

        let yaml = serde_yaml::to_string(&cache).expect("serialize");
        let restored: GateCache = serde_yaml::from_str(&yaml).expect("deserialize");

        let vk = signer.verifying_key();
        let reuse = restored.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(reuse.reusable, "signature must survive YAML roundtrip");
    }

    /// Direct `verify_gate` API works correctly.
    #[test]
    fn verify_gate_api() {
        let signer = Signer::generate();
        let cache = make_signed_cache(&signer);
        let vk = signer.verifying_key();

        assert!(cache.verify_gate("rustfmt", &vk).is_ok());

        let other = Signer::generate();
        assert!(
            cache
                .verify_gate("rustfmt", &other.verifying_key())
                .is_err()
        );
    }

    // --- TCK-00544: dirty-state cache poisoning regression tests ---

    /// Regression test: a cache entry seeded with a "dirty" attestation
    /// digest (simulating the old v1 git_blob-based input binding) must NOT
    /// be reusable when the pipeline presents a "clean" v2 file_sha256-based
    /// attestation digest for the same SHA.
    ///
    /// This proves that the attestation schema version bump from v1 to v2
    /// invalidates all pre-existing cache entries, closing the dirty-state
    /// cache poisoning vector.
    #[test]
    fn dirty_seeded_cache_entry_not_reusable_by_clean_attestation() {
        let sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let mut cache = GateCache::new(sha);

        let dirty_v1_digest = "v1_dirty_git_blob_based_attestation_digest_abc123";
        cache.set_with_attestation(
            "rustfmt",
            true,
            5,
            Some(dirty_v1_digest.to_string()),
            false,
            Some("evidence-log-digest".to_string()),
            None,
        );

        let clean_v2_digest = "v2_clean_file_sha256_based_attestation_digest_xyz789";
        let reuse = cache.check_reuse("rustfmt", Some(clean_v2_digest), true, None, false);

        assert!(
            !reuse.reusable,
            "dirty-seeded v1 cache entry must NOT be reusable with clean v2 digest"
        );
        assert_eq!(
            reuse.reason, "attestation_mismatch",
            "reuse denial must be due to attestation_mismatch, not any other reason"
        );
    }

    /// Verify that a cache entry without an attestation digest is never
    /// reusable — fail-closed behavior.
    #[test]
    fn cache_entry_without_attestation_digest_not_reusable() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            None, // no attestation digest
            false,
            Some("log-digest".to_string()),
            None,
        );

        let reuse = cache.check_reuse("rustfmt", Some("any-digest"), true, None, false);
        assert!(
            !reuse.reusable,
            "cache entry without attestation digest must not be reusable"
        );
        assert_eq!(
            reuse.reason, "attestation_mismatch",
            "reason must be attestation_mismatch when cached digest is None"
        );
    }

    /// Verify that missing `evidence_log_digest` prevents reuse even when
    /// attestation matches — defense in depth against incomplete cache
    /// entries.
    #[test]
    fn cache_entry_without_evidence_digest_not_reusable() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("matching-digest".to_string()),
            false,
            None, // no evidence log digest
            None,
        );

        let reuse = cache.check_reuse("rustfmt", Some("matching-digest"), true, None, false);
        assert!(
            !reuse.reusable,
            "cache entry without evidence log digest must not be reusable"
        );
        assert_eq!(
            reuse.reason, "evidence_digest_missing",
            "reason must be evidence_digest_missing"
        );
    }

    // --- TCK-00540: Legacy cache reuse policy tests ---

    /// Helper: create a signed cache whose entries have the receipt binding
    /// fields explicitly overridden. This allows testing the receipt binding
    /// gate in isolation (after the signature gate passes).
    fn make_signed_cache_with_bindings(signer: &Signer, rfc0028: bool, rfc0029: bool) -> GateCache {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("digest-1".to_string()),
            false,
            Some("log-digest".to_string()),
            None,
        );
        // Override the default-true bindings set by set_with_attestation.
        if let Some(entry) = cache.gates.get_mut("rustfmt") {
            entry.rfc0028_receipt_bound = rfc0028;
            entry.rfc0029_receipt_bound = rfc0029;
        }
        // Re-sign after mutation so the signature covers the updated fields.
        cache.sign_all(signer);
        cache
    }

    /// Signed cache entry (missing RFC-0028/0029 bindings) is denied by
    /// default (fail-closed). The entry is validly signed but lacks receipt
    /// bindings, simulating a pre-TCK-00540 cache entry that was resigned.
    #[test]
    fn legacy_entry_without_receipt_bindings_denied_by_default() {
        let signer = Signer::generate();
        let cache = make_signed_cache_with_bindings(&signer, false, false);
        let vk = signer.verifying_key();

        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse.reusable,
            "entry without receipt bindings must be denied by default"
        );
        assert_eq!(reuse.reason, "receipt_binding_missing");
    }

    /// Signed cache entry with `--allow-legacy-cache` override is accepted
    /// (unsafe migration path).
    #[test]
    fn legacy_entry_accepted_with_allow_legacy_cache_override() {
        let signer = Signer::generate();
        let cache = make_signed_cache_with_bindings(&signer, false, false);
        let vk = signer.verifying_key();

        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), true);
        assert!(
            reuse.reusable,
            "entry must be accepted with allow_legacy_cache override"
        );
        assert_eq!(reuse.reason, "legacy_cache_override_unsafe");
    }

    /// Entry with both RFC-0028 and RFC-0029 bindings passes the receipt
    /// binding gate regardless of the `allow_legacy_cache` flag.
    #[test]
    fn bound_entry_passes_receipt_binding_gate() {
        let signer = Signer::generate();
        let cache = make_signed_cache(&signer);
        let vk = signer.verifying_key();

        // With allow_legacy_cache = false (default deny).
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(reuse.reusable, "entry with both receipt bindings must pass");
        assert_eq!(reuse.reason, "attestation_match");

        // With allow_legacy_cache = true (override enabled).
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), true);
        assert!(
            reuse.reusable,
            "entry with both receipt bindings must pass even with override"
        );
        assert_eq!(reuse.reason, "attestation_match");
    }

    /// Entry with only RFC-0028 binding (missing RFC-0029) is denied.
    #[test]
    fn partial_binding_rfc0028_only_denied() {
        let signer = Signer::generate();
        let cache = make_signed_cache_with_bindings(&signer, true, false);
        let vk = signer.verifying_key();

        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse.reusable,
            "entry with only RFC-0028 binding must be denied"
        );
        assert_eq!(reuse.reason, "receipt_binding_missing");
    }

    /// YAML roundtrip preserves the TCK-00540 receipt binding fields.
    #[test]
    fn yaml_roundtrip_preserves_receipt_binding_fields() {
        let signer = Signer::generate();
        let cache = make_signed_cache(&signer);

        let yaml = serde_yaml::to_string(&cache).expect("serialize");
        let restored: GateCache = serde_yaml::from_str(&yaml).expect("deserialize");

        let entry = restored.gates.get("rustfmt").expect("entry exists");
        assert!(
            entry.rfc0028_receipt_bound,
            "rfc0028 binding must survive roundtrip"
        );
        assert!(
            entry.rfc0029_receipt_bound,
            "rfc0029 binding must survive roundtrip"
        );
        assert!(
            !entry.legacy_cache_override,
            "legacy_cache_override must survive roundtrip"
        );
    }

    /// Deserializing a legacy YAML entry without TCK-00540 fields defaults to
    /// `false` (fail-closed).
    #[test]
    fn deserialize_legacy_yaml_defaults_to_unbound() {
        let yaml = r#"
sha: abc123
gates:
  rustfmt:
    status: PASS
    duration_secs: 1
    completed_at: "2024-01-01T00:00:00Z"
    attestation_digest: "digest-1"
    evidence_log_digest: "log-digest"
"#;
        let cache: GateCache = serde_yaml::from_str(yaml).expect("deserialize legacy YAML");
        let entry = cache.gates.get("rustfmt").expect("entry exists");
        assert!(
            !entry.rfc0028_receipt_bound,
            "legacy YAML without rfc0028_receipt_bound must default to false"
        );
        assert!(
            !entry.rfc0029_receipt_bound,
            "legacy YAML without rfc0029_receipt_bound must default to false"
        );
        assert!(
            !entry.legacy_cache_override,
            "legacy YAML without legacy_cache_override must default to false"
        );
    }

    // --- TCK-00540 fix round 2: mark_legacy_override tests ---

    /// `mark_legacy_override` sets the correct binding flags on a cache entry
    /// that was initially written with default trusted bindings.
    #[test]
    fn mark_legacy_override_preserves_audit_trail() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("digest-1".to_string()),
            false,
            Some("log-digest".to_string()),
            None,
        );

        // Before mark: default trusted bindings.
        let entry = cache.gates.get("rustfmt").expect("entry exists");
        assert!(entry.rfc0028_receipt_bound, "default should be true");
        assert!(entry.rfc0029_receipt_bound, "default should be true");
        assert!(!entry.legacy_cache_override, "default should be false");

        // After mark: override audit trail preserved.
        cache.mark_legacy_override("rustfmt");
        let entry = cache.gates.get("rustfmt").expect("entry exists");
        assert!(
            !entry.rfc0028_receipt_bound,
            "rfc0028 must be false after mark_legacy_override"
        );
        assert!(
            !entry.rfc0029_receipt_bound,
            "rfc0029 must be false after mark_legacy_override"
        );
        assert!(
            entry.legacy_cache_override,
            "legacy_cache_override must be true after mark_legacy_override"
        );
    }

    /// After `mark_legacy_override`, the entry must be denied by a default-mode
    /// `check_reuse` (the whole point of the fix: one unsafe run must not erase
    /// that the result lacked RFC-0028/0029 bindings).
    #[test]
    fn override_marked_entry_denied_by_default_mode() {
        let signer = Signer::generate();
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("digest-1".to_string()),
            false,
            Some("log-digest".to_string()),
            None,
        );
        cache.mark_legacy_override("rustfmt");
        // Re-sign after mutation so signature covers the updated fields.
        cache.sign_all(&signer);

        let vk = signer.verifying_key();

        // Default mode (allow_legacy_cache=false): must deny.
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse.reusable,
            "override-marked entry must be denied in default mode"
        );
        assert_eq!(
            reuse.reason, "receipt_binding_missing",
            "reason must be receipt_binding_missing"
        );

        // Override mode (allow_legacy_cache=true): must accept.
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), true);
        assert!(
            reuse.reusable,
            "override-marked entry must be accepted with override"
        );
        assert_eq!(reuse.reason, "legacy_cache_override_unsafe");
    }

    /// `mark_legacy_override` on a nonexistent gate is a no-op (no panic).
    #[test]
    fn mark_legacy_override_nonexistent_gate_is_noop() {
        let mut cache = GateCache::new("abc123");
        // Should not panic.
        cache.mark_legacy_override("nonexistent");
        assert!(cache.gates.is_empty());
    }

    /// YAML roundtrip preserves override-marked entry fields.
    #[test]
    fn yaml_roundtrip_preserves_override_marked_entry() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("digest-1".to_string()),
            false,
            Some("log-digest".to_string()),
            None,
        );
        cache.mark_legacy_override("rustfmt");

        let yaml = serde_yaml::to_string(&cache).expect("serialize");
        let restored: GateCache = serde_yaml::from_str(&yaml).expect("deserialize");

        let entry = restored.gates.get("rustfmt").expect("entry exists");
        assert!(
            !entry.rfc0028_receipt_bound,
            "rfc0028 must be false after roundtrip of override-marked entry"
        );
        assert!(
            !entry.rfc0029_receipt_bound,
            "rfc0029 must be false after roundtrip of override-marked entry"
        );
        assert!(
            entry.legacy_cache_override,
            "legacy_cache_override must be true after roundtrip of override-marked entry"
        );
    }
}
