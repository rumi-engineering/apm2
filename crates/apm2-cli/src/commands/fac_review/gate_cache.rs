//! Per-SHA evidence gate result cache with attestation-aware reuse.
//!
//! Stores one file per gate under:
//! `~/.apm2/private/fac/gate_cache_v2/{sha}/{gate}.yaml`.
//!
//! # Signed Receipts (TCK-00576)
//!
//! Each `CachedGateResult` carries an optional Ed25519 signature over the
//! canonical bytes of the receipt entry (domain-separated with
//! `GATE_CACHE_RECEIPT:`).  In default mode, `check_reuse` requires a
//! valid signature — unsigned or forged entries are rejected for cache
//! reuse (fail-closed).
//!
//! # Cache Reuse Policy (TCK-00540)
//!
//! Gate cache entries are treated as **untrusted** unless they carry
//! RFC-0028 authorization and RFC-0029 admission receipt bindings
//! (`rfc0028_receipt_bound` and `rfc0029_receipt_bound` fields).
//!
//! In default mode, `check_reuse` rejects entries missing these bindings
//! (fail-closed).

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
#[serde(deny_unknown_fields)]
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
    /// Whether this cache entry is bound to an RFC-0028 authorization receipt.
    pub rfc0028_receipt_bound: bool,
    /// Whether this cache entry is bound to an RFC-0029 admission receipt.
    pub rfc0029_receipt_bound: bool,
}

impl CachedGateResult {
    /// Returns deterministic canonical bytes for signing/verification.
    ///
    /// Includes all fields that are semantically meaningful for the gate
    /// result's integrity (the signed content). `signature_hex` and
    /// `signer_id` are excluded (they are the authentication envelope,
    /// not the authenticated content).
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

        // Policy flags are always covered by the signature.
        buf.push(u8::from(self.rfc0028_receipt_bound));
        buf.push(u8::from(self.rfc0029_receipt_bound));

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
    ///
    /// Policy flags are included in canonical bytes; callers must set final
    /// receipt-binding values before signing.
    pub fn sign(&mut self, signer: &Signer, sha: &str, gate_name: &str) {
        let canonical = self.canonical_bytes(sha, gate_name);
        let sig = sign_with_domain(signer, GATE_CACHE_RECEIPT_PREFIX, &canonical);
        self.signature_hex = Some(hex::encode(sig.to_bytes()));
        self.signer_id = Some(hex::encode(signer.verifying_key().to_bytes()));
    }

    /// Verify the signature on this entry against the expected verifying key.
    ///
    /// Returns `Ok(())` on success, or `Err` with a human-readable reason.
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

        // Decode signature.
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
        .map_err(|_err| "signature verification failed".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GateCacheEntryV2 {
    schema: String,
    sha: String,
    gate_name: String,
    result: CachedGateResult,
}

/// Per-SHA gate cache containing results for all executed gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// Load cache from disk for the given SHA. Returns `None` if not found or
    /// unparseable.
    pub fn load(sha: &str) -> Option<Self> {
        let _lock = acquire_sha_lock(sha, false).ok()?;
        Self::load_v2_unlocked(sha)
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
    /// New entries are written with **fail-closed** defaults:
    /// `rfc0028_receipt_bound = false` and `rfc0029_receipt_bound = false`.
    /// These flags are only promoted to `true` after a receipt lookup
    /// confirms that a corresponding RFC-0028/0029 receipt exists in the
    /// durable receipt store (see [`Self::try_bind_receipt_from_store`]).
    ///
    /// If no receipt can be found at write time, the entry persists with
    /// `false` flags and is denied by `check_reuse` (fail-closed).
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
                // TCK-00540 BLOCKER fix: fail-closed defaults. Receipt
                // bindings are only promoted to `true` by an explicit
                // `bind_receipt_evidence` or `try_bind_receipt_from_store`
                // call after verifying receipt existence.
                rfc0028_receipt_bound: false,
                rfc0029_receipt_bound: false,
            },
        );
    }

    /// Explicitly bind RFC-0028/0029 receipt evidence to a cache entry.
    ///
    /// Sets `rfc0028_receipt_bound` and `rfc0029_receipt_bound` to the
    /// provided values. This must be called **after** `set_with_attestation`
    /// and **before** `sign()` / `sign_all()` so the signed canonical
    /// bytes reflect the final flag values.
    ///
    /// Callers are responsible for verifying that receipt evidence actually
    /// exists before passing `true`. Passing `true` without verified
    /// evidence defeats the fail-closed posture.
    pub fn bind_receipt_evidence(&mut self, gate: &str, rfc0028: bool, rfc0029: bool) {
        if let Some(entry) = self.gates.get_mut(gate) {
            entry.rfc0028_receipt_bound = rfc0028;
            entry.rfc0029_receipt_bound = rfc0029;
        }
    }

    /// Best-effort receipt lookup: scan the durable receipt store for a job
    /// receipt matching `job_id` and promote receipt binding flags on all
    /// gate entries in this cache.
    ///
    /// If a receipt is found with both `rfc0028_channel_boundary` (with
    /// `passed == true`) and `eio29_queue_admission` (with `verdict ==
    /// "allow"`), all entries are promoted to `rfc0028=true, rfc0029=true`.
    ///
    /// If the receipt is missing, or evidence fields are absent/failed, the
    /// flags remain `false` (fail-closed).
    ///
    /// **CRITICAL:** This method **must** be called **before** `sign()`
    /// / `sign_all()` so that the signed canonical bytes cover the final
    /// flag values.
    #[cfg_attr(test, allow(dead_code))]
    pub fn try_bind_receipt_from_store(&mut self, receipts_dir: &std::path::Path, job_id: &str) {
        let Some(receipt) = apm2_core::fac::lookup_job_receipt(receipts_dir, job_id) else {
            return; // No receipt found — flags stay false (fail-closed).
        };

        let rfc0028_ok = receipt
            .rfc0028_channel_boundary
            .as_ref()
            .is_some_and(|trace| trace.passed);
        let rfc0029_ok = receipt
            .eio29_queue_admission
            .as_ref()
            .is_some_and(|trace| trace.verdict == "allow");

        if rfc0028_ok && rfc0029_ok {
            // Collect gate names to avoid borrow conflict with bind_receipt_evidence.
            let gate_names: Vec<String> = self.gates.keys().cloned().collect();
            for gate_name in &gate_names {
                self.bind_receipt_evidence(gate_name, true, true);
            }
        }
        // If either check fails, flags remain false — fail-closed.
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
    pub fn check_reuse(
        &self,
        gate: &str,
        expected_attestation_digest: Option<&str>,
        require_full_mode: bool,
        verifying_key: Option<&VerifyingKey>,
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
            match cached.verify(key, &self.sha, gate) {
                Ok(()) => {},
                Err(_reason) => {
                    return ReuseDecision::miss("signature_invalid");
                },
            }
        } else {
            // No verifying key provided: unsigned receipts cannot be reused
            // in any mode.  Fail closed.
            if cached.signature_hex.is_none() {
                return ReuseDecision::miss("signature_missing");
            }
        }

        // TCK-00540: RFC-0028/0029 receipt binding gate (fail-closed).
        if !cached.rfc0028_receipt_bound || !cached.rfc0029_receipt_bound {
            return ReuseDecision::miss("receipt_binding_missing");
        }

        ReuseDecision::hit()
    }

    /// Verify a specific gate receipt against the expected verifying key.
    ///
    /// Returns `Ok(())` on success, or `Err(reason)` on failure.
    /// Used by the `apm2 fac receipts verify` CLI command.
    #[allow(dead_code)]
    pub fn verify_gate(&self, gate: &str, verifying_key: &VerifyingKey) -> Result<(), String> {
        let cached = self
            .get(gate)
            .ok_or_else(|| format!("no cached result for gate '{gate}'"))?;
        cached.verify(verifying_key, &self.sha, gate)
    }
}

/// Post-receipt gate cache rebinding (TCK-00540 BLOCKER fix).
///
/// After a worker creates a job receipt with RFC-0028/0029 bindings, this
/// function reloads the gate cache for the given SHA, promotes the receipt
/// binding flags based on the durable receipt, re-signs the cache, and
/// persists it.
///
/// If the gate cache or receipt cannot be found, or the receipt lacks the
/// required bindings, this is a no-op (fail-closed: the cache retains its
/// existing `false` flags).
///
/// # Arguments
///
/// * `sha` - The commit SHA whose gate cache should be rebound.
/// * `receipts_dir` - Path to the receipt store
///   (`$APM2_HOME/private/fac/receipts`).
/// * `job_id` - The job ID whose receipt should be looked up.
/// * `signer` - The signing key for re-signing the cache after flag promotion.
#[cfg_attr(test, allow(dead_code))]
pub fn rebind_gate_cache_after_receipt(
    sha: &str,
    receipts_dir: &Path,
    job_id: &str,
    signer: &Signer,
) {
    let Some(mut cache) = GateCache::load(sha) else {
        return; // No cache on disk — nothing to rebind.
    };
    cache.try_bind_receipt_from_store(receipts_dir, job_id);

    // Only re-sign and save if at least one gate was promoted.
    let any_bound = cache
        .gates
        .values()
        .any(|entry| entry.rfc0028_receipt_bound && entry.rfc0029_receipt_bound);
    if any_bound {
        cache.sign_all(signer);
        let _ = cache.save(); // Best-effort: failure is non-fatal.
    }
}

#[cfg(test)]
mod tests {
    use apm2_core::crypto::Signer;

    use super::{CachedGateResult, GateCache, ReuseDecision};

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
        cache.bind_receipt_evidence("rustfmt", true, true);
        cache.sign_all(signer);
        cache
    }

    fn sample_entry() -> CachedGateResult {
        CachedGateResult {
            status: "PASS".to_string(),
            duration_secs: 42,
            completed_at: "2026-01-01T00:00:00Z".to_string(),
            attestation_digest: Some("digest".to_string()),
            evidence_log_digest: Some("evidence".to_string()),
            quick_mode: Some(false),
            log_bundle_hash: None,
            bytes_written: None,
            bytes_total: None,
            was_truncated: None,
            log_path: None,
            signature_hex: None,
            signer_id: None,
            rfc0028_receipt_bound: true,
            rfc0029_receipt_bound: true,
        }
    }

    #[test]
    fn test_gate_cache_new_is_empty() {
        let cache = GateCache::new("abc123");
        assert_eq!(cache.sha, "abc123");
        assert!(cache.gates.is_empty());
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
        cache.bind_receipt_evidence("rustfmt", true, true);

        let yaml = serde_yaml::to_string(&cache).expect("serialize");
        let restored: GateCache = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(restored.sha, "deadbeef1234567890");
        assert_eq!(restored.gates.len(), 1);
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
            cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk)),
            ReuseDecision::hit()
        );
        assert_eq!(
            cache
                .check_reuse("rustfmt", Some("digest-2"), true, Some(&vk))
                .reason,
            "attestation_mismatch"
        );
        assert_eq!(
            cache
                .check_reuse("merge_conflict_main", Some("digest-1"), true, Some(&vk))
                .reason,
            "policy_merge_conflict_recompute"
        );
    }

    #[test]
    fn signed_receipt_valid_reuse() {
        let signer = Signer::generate();
        let cache = make_signed_cache(&signer);
        let vk = signer.verifying_key();
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk));
        assert!(reuse.reusable);
        assert_eq!(reuse.reason, "attestation_match");
    }

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
        cache.bind_receipt_evidence("rustfmt", true, true);

        let vk = signer.verifying_key();
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk));
        assert!(!reuse.reusable);
        assert_eq!(reuse.reason, "signature_invalid");
    }

    #[test]
    fn forged_receipt_wrong_key_rejected() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let cache = make_signed_cache(&signer_a);
        let vk_b = signer_b.verifying_key();
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk_b));
        assert!(!reuse.reusable);
        assert_eq!(reuse.reason, "signature_invalid");
    }

    #[test]
    fn tampered_receipt_rejected() {
        let signer = Signer::generate();
        let mut cache = make_signed_cache(&signer);

        if let Some(entry) = cache.gates.get_mut("rustfmt") {
            entry.attestation_digest = Some("tampered-digest".to_string());
        }

        let vk = signer.verifying_key();
        let reuse = cache.check_reuse("rustfmt", Some("tampered-digest"), true, Some(&vk));
        assert!(!reuse.reusable);
        assert_eq!(reuse.reason, "signature_invalid");
    }

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
        cache.bind_receipt_evidence("rustfmt", true, true);

        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, None);
        assert!(!reuse.reusable);
        assert_eq!(reuse.reason, "signature_missing");
    }

    #[test]
    fn sign_serialize_deserialize_verify_roundtrip() {
        let signer = Signer::generate();
        let cache = make_signed_cache(&signer);

        let yaml = serde_yaml::to_string(&cache).expect("serialize");
        let restored: GateCache = serde_yaml::from_str(&yaml).expect("deserialize");

        let vk = signer.verifying_key();
        let reuse = restored.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk));
        assert!(reuse.reusable);
    }

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

    #[test]
    fn cache_entry_without_attestation_digest_not_reusable() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            None,
            false,
            Some("log-digest".to_string()),
            None,
        );
        cache.bind_receipt_evidence("rustfmt", true, true);

        let reuse = cache.check_reuse("rustfmt", Some("any-digest"), true, None);
        assert!(!reuse.reusable);
        assert_eq!(reuse.reason, "attestation_mismatch");
    }

    #[test]
    fn cache_entry_without_evidence_digest_not_reusable() {
        let mut cache = GateCache::new("abc123");
        cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("matching-digest".to_string()),
            false,
            None,
            None,
        );
        cache.bind_receipt_evidence("rustfmt", true, true);

        let reuse = cache.check_reuse("rustfmt", Some("matching-digest"), true, None);
        assert!(!reuse.reusable);
        assert_eq!(reuse.reason, "evidence_digest_missing");
    }

    #[test]
    fn set_with_attestation_defaults_to_fail_closed() {
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

        let entry = cache.gates.get("rustfmt").expect("entry exists");
        assert!(!entry.rfc0028_receipt_bound);
        assert!(!entry.rfc0029_receipt_bound);
    }

    #[test]
    fn default_mode_denies_when_receipt_binding_absent() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();

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
        cache.sign_all(&signer);

        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk));
        assert!(!reuse.reusable);
        assert_eq!(reuse.reason, "receipt_binding_missing");
    }

    #[test]
    fn bind_receipt_evidence_enables_default_mode_reuse() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();

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
        cache.bind_receipt_evidence("rustfmt", true, true);
        cache.sign_all(&signer);

        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk));
        assert!(reuse.reusable);
        assert_eq!(reuse.reason, "attestation_match");
    }

    #[test]
    fn canonical_bytes_changes_when_receipt_binding_flags_change() {
        let mut entry = sample_entry();
        let bytes_bound = entry.canonical_bytes("sha1", "gate1");

        entry.rfc0028_receipt_bound = false;
        entry.rfc0029_receipt_bound = false;
        let bytes_unbound = entry.canonical_bytes("sha1", "gate1");

        assert_ne!(bytes_bound, bytes_unbound);
    }

    #[test]
    fn deny_unknown_fields_rejects_unknown_cached_gate_field() {
        let yaml = r#"
sha: abc123
gates:
  rustfmt:
    status: PASS
    duration_secs: 1
    completed_at: "2024-01-01T00:00:00Z"
    attestation_digest: "digest-1"
    evidence_log_digest: "log-digest"
    rfc0028_receipt_bound: true
    rfc0029_receipt_bound: true
    unknown_field: true
"#;
        let parsed: Result<GateCache, _> = serde_yaml::from_str(yaml);
        assert!(parsed.is_err());
    }

    #[test]
    fn deserialize_missing_receipt_binding_fields_is_rejected() {
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
        let parsed: Result<GateCache, _> = serde_yaml::from_str(yaml);
        assert!(parsed.is_err());
    }
}
