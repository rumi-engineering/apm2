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

/// Controls which fields are included in the canonical bytes for
/// signing/verification (TCK-00540 BLOCKER fix).
///
/// - `WithPolicyFlags`: includes `rfc0028_receipt_bound`,
///   `rfc0029_receipt_bound`, and `legacy_cache_override` in the signed
///   content. Used for **new entries** written after this fix.
/// - `WithoutPolicyFlags`: excludes those three fields. Used as a **fallback**
///   for legacy entries signed before this fix.
///
/// Dual-format verification:
/// 1. Try `WithPolicyFlags` first — succeeds for new entries.
/// 2. Fall back to `WithoutPolicyFlags` — succeeds for old entries; if this
///    matches, the entry is treated as having all policy flags set to `false`
///    regardless of what the YAML says.
/// 3. If neither format verifies — hard deny (signature invalid).
///
/// Tamper resistance:
/// - If an attacker flips `rfc0028_receipt_bound=true` in a legacy entry
///   (signed without flags), the `WithoutPolicyFlags` canonical bytes ignore
///   the flip — policy enforcement correctly uses `false`.
/// - If they flip a flag on a new entry, the `WithPolicyFlags` canonical bytes
///   cover the flip — verification fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CanonicalBytesFormat {
    /// New format: policy flags are included in canonical bytes.
    WithPolicyFlags,
    /// Legacy format: policy flags are excluded from canonical bytes.
    WithoutPolicyFlags,
}

impl CachedGateResult {
    /// Returns deterministic canonical bytes for signing/verification.
    ///
    /// Includes all fields that are semantically meaningful for the gate
    /// result's integrity (the signed content). `signature_hex` and
    /// `signer_id` are excluded (they are the authentication envelope,
    /// not the authenticated content).
    ///
    /// **TCK-00540 (BLOCKER fix):** The `format` parameter controls
    /// whether `rfc0028_receipt_bound`, `rfc0029_receipt_bound`, and
    /// `legacy_cache_override` are included:
    ///
    /// - `WithPolicyFlags` (new entries): these three booleans are appended to
    ///   the canonical bytes, cryptographically binding them to the signature.
    ///   Tampering with policy flags after signing invalidates the signature.
    ///
    /// - `WithoutPolicyFlags` (legacy fallback): these fields are excluded,
    ///   preserving backward compatibility with entries signed before this fix
    ///   existed.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn canonical_bytes(&self, sha: &str, gate_name: &str, format: CanonicalBytesFormat) -> Vec<u8> {
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

        // TCK-00540 BLOCKER fix: cryptographically bind policy flags
        // in new-format entries. Legacy entries omit these fields.
        if format == CanonicalBytesFormat::WithPolicyFlags {
            buf.push(u8::from(self.rfc0028_receipt_bound));
            buf.push(u8::from(self.rfc0029_receipt_bound));
            buf.push(u8::from(self.legacy_cache_override));
        }

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
    /// **TCK-00540 BLOCKER fix:** Signs with `WithPolicyFlags` format,
    /// cryptographically binding `rfc0028_receipt_bound`,
    /// `rfc0029_receipt_bound`, and `legacy_cache_override` to the
    /// signature. Callers **must** set final policy flag values (e.g.,
    /// via `mark_legacy_override`) **before** calling `sign`.
    pub fn sign(&mut self, signer: &Signer, sha: &str, gate_name: &str) {
        let canonical = self.canonical_bytes(sha, gate_name, CanonicalBytesFormat::WithPolicyFlags);
        let sig = sign_with_domain(signer, GATE_CACHE_RECEIPT_PREFIX, &canonical);
        self.signature_hex = Some(hex::encode(sig.to_bytes()));
        self.signer_id = Some(hex::encode(signer.verifying_key().to_bytes()));
    }

    /// Verify the signature on this entry against the expected verifying key.
    ///
    /// Returns `Ok(format)` indicating which canonical bytes format was
    /// used for successful verification, or `Err` with a human-readable
    /// reason on any failure.
    ///
    /// **TCK-00540 BLOCKER fix — dual-format verification:**
    ///
    /// 1. First attempt: verify with `WithPolicyFlags` canonical bytes.
    ///    Succeeds for new entries written after this fix.
    /// 2. Fallback: verify with `WithoutPolicyFlags` canonical bytes. Succeeds
    ///    for legacy entries signed before this fix.
    /// 3. If neither format verifies: hard deny (signature invalid).
    ///
    /// The caller (`check_reuse`) uses the returned format to decide
    /// policy flag trust:
    /// - `WithPolicyFlags`: trust the YAML values (they're signed).
    /// - `WithoutPolicyFlags`: treat all policy flags as `false` regardless of
    ///   YAML values (prevents tamper bypass).
    pub fn verify(
        &self,
        expected_key: &VerifyingKey,
        sha: &str,
        gate_name: &str,
    ) -> Result<CanonicalBytesFormat, String> {
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

        // Decode signature (shared between both verification attempts).
        let sig_bytes =
            hex::decode(sig_hex).map_err(|e| format!("invalid signature_hex hex: {e}"))?;
        let signature = apm2_core::crypto::parse_signature(&sig_bytes)
            .map_err(|e| format!("malformed signature: {e}"))?;

        // TCK-00540 BLOCKER fix: dual-format verification.
        // Attempt 1: new format (policy flags included in signed content).
        let canonical_new =
            self.canonical_bytes(sha, gate_name, CanonicalBytesFormat::WithPolicyFlags);
        if verify_with_domain(
            expected_key,
            GATE_CACHE_RECEIPT_PREFIX,
            &canonical_new,
            &signature,
        )
        .is_ok()
        {
            return Ok(CanonicalBytesFormat::WithPolicyFlags);
        }

        // Attempt 2: legacy format (policy flags excluded from signed content).
        let canonical_legacy =
            self.canonical_bytes(sha, gate_name, CanonicalBytesFormat::WithoutPolicyFlags);
        if verify_with_domain(
            expected_key,
            GATE_CACHE_RECEIPT_PREFIX,
            &canonical_legacy,
            &signature,
        )
        .is_ok()
        {
            return Ok(CanonicalBytesFormat::WithoutPolicyFlags);
        }

        // Neither format verified — hard deny.
        Err("signature verification failed (both new and legacy formats)".to_string())
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
    ///
    /// **CRITICAL:** This method **must** be called **before** `sign()`
    /// / `sign_all()`. Policy flags are now included in the signed
    /// canonical bytes (`WithPolicyFlags` format), so the signature
    /// must cover the final flag values.
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
        // TCK-00540 BLOCKER fix: dual-format verification determines whether
        // to trust YAML policy flags or treat them as `false`.
        let verified_format = if let Some(key) = verifying_key {
            match cached.verify(key, &self.sha, gate) {
                Ok(format) => Some(format),
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
            None
        };

        // TCK-00540 BLOCKER fix: determine effective policy flag values.
        //
        // - If verified with `WithPolicyFlags` (new entry): trust YAML values because
        //   they are cryptographically bound to the signature. Tampering invalidates
        //   the signature.
        //
        // - If verified with `WithoutPolicyFlags` (legacy entry): treat all policy
        //   flags as `false` regardless of YAML values. An attacker who flips
        //   `rfc0028_receipt_bound=true` in the YAML of a legacy entry cannot bypass
        //   the policy gate because the effective value is always `false` for
        //   legacy-format entries.
        //
        // - If no verifying key was provided (no format info): use YAML values as-is
        //   (this path already failed closed on unsigned entries above, so this only
        //   applies to signed entries verified without a key, which is a test-only
        //   path).
        let (effective_rfc0028, effective_rfc0029) = match verified_format {
            Some(CanonicalBytesFormat::WithPolicyFlags) => {
                // New format: YAML values are signed — trust them.
                (cached.rfc0028_receipt_bound, cached.rfc0029_receipt_bound)
            },
            Some(CanonicalBytesFormat::WithoutPolicyFlags) => {
                // Legacy format: YAML values are NOT signed — treat as false.
                (false, false)
            },
            None => {
                // No verification performed (test-only path).
                (cached.rfc0028_receipt_bound, cached.rfc0029_receipt_bound)
            },
        };

        // TCK-00540: RFC-0028/0029 receipt binding gate (fail-closed by
        // default). Cache entries without both receipt bindings are treated
        // as untrusted legacy entries. The `--allow-legacy-cache` flag
        // permits unsafe override for migration.
        if !effective_rfc0028 || !effective_rfc0029 {
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
    /// Returns `Ok(format)` indicating which canonical bytes format was
    /// used for successful verification, or `Err(reason)` on failure.
    /// Used by the `apm2 fac receipts verify` CLI command.
    #[allow(dead_code)]
    pub fn verify_gate(
        &self,
        gate: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<CanonicalBytesFormat, String> {
        let cached = self
            .get(gate)
            .ok_or_else(|| format!("no cached result for gate '{gate}'"))?;
        cached.verify(verifying_key, &self.sha, gate)
    }
}

#[cfg(test)]
mod tests {
    use apm2_core::crypto::Signer;

    use super::{CachedGateResult, CanonicalBytesFormat, GateCache, ReuseDecision};

    /// Create a signed cache using the NEW format (`WithPolicyFlags`).
    /// The entry has `rfc0028=true, rfc0029=true, legacy_cache_override=false`.
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

    /// Create a signed cache using the LEGACY format (`WithoutPolicyFlags`)
    /// to simulate pre-BLOCKER-fix entries that exist on disk.
    /// Then set the YAML policy flags to the requested values.
    fn make_legacy_signed_cache_with_bindings(
        signer: &Signer,
        rfc0028: bool,
        rfc0029: bool,
    ) -> GateCache {
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
        // Sign using LEGACY format to simulate a pre-BLOCKER-fix entry.
        let sha = cache.sha.clone();
        for (gate_name, result) in &mut cache.gates {
            let canonical =
                result.canonical_bytes(&sha, gate_name, CanonicalBytesFormat::WithoutPolicyFlags);
            let sig = apm2_core::fac::sign_with_domain(
                signer,
                apm2_core::fac::GATE_CACHE_RECEIPT_PREFIX,
                &canonical,
            );
            result.signature_hex = Some(hex::encode(sig.to_bytes()));
            result.signer_id = Some(hex::encode(signer.verifying_key().to_bytes()));
        }
        // Set the YAML flag values.
        if let Some(entry) = cache.gates.get_mut("rustfmt") {
            entry.rfc0028_receipt_bound = rfc0028;
            entry.rfc0029_receipt_bound = rfc0029;
        }
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

    /// Legacy signed cache entry (missing RFC-0028/0029 bindings) is denied by
    /// default (fail-closed). The entry is signed with the legacy format
    /// (`WithoutPolicyFlags`), so `check_reuse` detects it as legacy and
    /// forces effective policy flags to `false`, denying reuse.
    #[test]
    fn legacy_entry_without_receipt_bindings_denied_by_default() {
        let signer = Signer::generate();
        let cache = make_legacy_signed_cache_with_bindings(&signer, false, false);
        let vk = signer.verifying_key();

        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse.reusable,
            "entry without receipt bindings must be denied by default"
        );
        assert_eq!(reuse.reason, "receipt_binding_missing");
    }

    /// Legacy signed cache entry with `--allow-legacy-cache` override is
    /// accepted (unsafe migration path).
    #[test]
    fn legacy_entry_accepted_with_allow_legacy_cache_override() {
        let signer = Signer::generate();
        let cache = make_legacy_signed_cache_with_bindings(&signer, false, false);
        let vk = signer.verifying_key();

        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), true);
        assert!(
            reuse.reusable,
            "entry must be accepted with allow_legacy_cache override"
        );
        assert_eq!(reuse.reason, "legacy_cache_override_unsafe");
    }

    /// New-format entry with both RFC-0028 and RFC-0029 bindings passes the
    /// receipt binding gate regardless of the `allow_legacy_cache` flag.
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

    /// Legacy entry with only RFC-0028 binding (missing RFC-0029) is denied.
    /// Since this is a legacy-format entry, effective flags are forced to
    /// `false` regardless of YAML values — so both bindings are missing.
    #[test]
    fn partial_binding_rfc0028_only_denied() {
        let signer = Signer::generate();
        let cache = make_legacy_signed_cache_with_bindings(&signer, true, false);
        let vk = signer.verifying_key();

        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse.reusable,
            "legacy entry with only RFC-0028 binding must be denied"
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
    ///
    /// **Production flow:** `mark_legacy_override` is called **before**
    /// `sign_all`, so the signed canonical bytes include the override
    /// flags (`rfc0028=false, rfc0029=false, legacy_cache_override=true`).
    /// The new-format signature covers these values.
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
        // Production flow: mark_legacy_override BEFORE sign_all.
        // The signature covers the override flag values.
        cache.mark_legacy_override("rustfmt");
        cache.sign_all(&signer);

        let vk = signer.verifying_key();

        // Default mode (allow_legacy_cache=false): must deny via policy gate.
        // Signature verifies as WithPolicyFlags (new format), so YAML values
        // are trusted — rfc0028=false, rfc0029=false causes denial.
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

    // --- TCK-00540 fix round 3+4: End-to-end runtime behaviour regression tests
    // ---

    /// Regression test proving the `--allow-legacy-cache` flag changes runtime
    /// behavior for the `fac gates` path. This is the key test from the BLOCKER
    /// finding: an unbound legacy entry must (a) be denied in default mode,
    /// (b) be accepted and stored with `legacy_cache_override=true` when the
    /// flag is set, and (c) subsequent default-mode runs must still deny the
    /// override-marked entry.
    ///
    /// Uses `make_legacy_signed_cache_with_bindings` to create entries signed
    /// with the legacy `WithoutPolicyFlags` format, as would exist on disk
    /// from pre-BLOCKER-fix gate runs.
    #[test]
    fn allow_legacy_cache_flag_changes_runtime_behaviour() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();

        // Simulate a pre-existing legacy-signed cache entry WITHOUT receipt
        // bindings (as would exist from a pre-BLOCKER-fix gate run).
        let cache = make_legacy_signed_cache_with_bindings(&signer, false, false);

        // (a) Default mode (allow_legacy_cache=false): MUST deny.
        // Signature verifies via legacy format fallback, so effective
        // flags are forced to false → receipt_binding_missing.
        let reuse_default = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse_default.reusable,
            "unbound legacy entry must be DENIED in default mode"
        );
        assert_eq!(
            reuse_default.reason, "receipt_binding_missing",
            "denial reason must be receipt_binding_missing"
        );

        // (b) Override mode (allow_legacy_cache=true): MUST accept.
        let reuse_override = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), true);
        assert!(
            reuse_override.reusable,
            "unbound legacy entry must be ACCEPTED with --allow-legacy-cache"
        );
        assert_eq!(
            reuse_override.reason, "legacy_cache_override_unsafe",
            "acceptance reason must be legacy_cache_override_unsafe"
        );

        // Simulate what run_gates_inner does after an override hit:
        // write the gate result, mark_legacy_override, THEN sign_all.
        // (Production flow: mark BEFORE sign.)
        let mut new_cache = GateCache::new("abc123");
        new_cache.set_with_attestation(
            "rustfmt",
            true,
            1,
            Some("digest-1".to_string()),
            false,
            Some("log-digest".to_string()),
            None,
        );
        // Mark override FIRST (production flow).
        new_cache.mark_legacy_override("rustfmt");
        // THEN sign — signature covers the override flags.
        new_cache.sign_all(&signer);

        // Verify the persisted entry has correct override markings.
        let entry = new_cache.gates.get("rustfmt").expect("entry must exist");
        assert!(
            !entry.rfc0028_receipt_bound,
            "override-marked entry must have rfc0028_receipt_bound=false"
        );
        assert!(
            !entry.rfc0029_receipt_bound,
            "override-marked entry must have rfc0029_receipt_bound=false"
        );
        assert!(
            entry.legacy_cache_override,
            "override-marked entry must have legacy_cache_override=true"
        );

        // (c) Subsequent default-mode run: MUST still deny the
        // override-marked entry. The new-format signature is valid and
        // the signed policy flags say rfc0028=false, rfc0029=false.
        let reuse_subsequent =
            new_cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse_subsequent.reusable,
            "override-marked entry must be DENIED in subsequent default-mode run"
        );
        assert_eq!(
            reuse_subsequent.reason, "receipt_binding_missing",
            "subsequent denial must be receipt_binding_missing"
        );
    }

    // --- TCK-00540 BLOCKER fix: dual-format verification and tamper resistance ---

    /// BLOCKER regression test 1: Mutating policy flags on a NEW-format
    /// signed entry invalidates the signature (tamper detection).
    ///
    /// A new-format entry has its policy flags included in `canonical_bytes`.
    /// An attacker who flips `rfc0028_receipt_bound` from `false` to `true`
    /// in the YAML breaks the `WithPolicyFlags` signature. The fallback
    /// `WithoutPolicyFlags` verification also fails because the original
    /// signature was computed over the longer `WithPolicyFlags` content.
    /// Result: `signature_invalid` (hard deny).
    #[test]
    fn tamper_new_entry_policy_flags_causes_signature_invalid() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();

        // Create a new-format entry with override markings (rfc0028=false,
        // rfc0029=false, legacy_cache_override=true) signed WITH policy flags.
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
        cache.sign_all(&signer);

        // Sanity: signature verifies before tampering.
        let entry = cache.get("rustfmt").expect("entry exists");
        let format = entry.verify(&vk, "abc123", "rustfmt").expect("must verify");
        assert_eq!(
            format,
            CanonicalBytesFormat::WithPolicyFlags,
            "new entry must verify as WithPolicyFlags"
        );

        // Tamper: flip rfc0028 from false to true (attacker tries to
        // bypass the policy gate).
        if let Some(entry) = cache.gates.get_mut("rustfmt") {
            entry.rfc0028_receipt_bound = true;
            entry.rfc0029_receipt_bound = true;
        }

        // Verification MUST fail: WithPolicyFlags fails because the
        // signed flags were (false,false,true) but YAML now says
        // (true,true,true). WithoutPolicyFlags fails because the
        // original signature was over the longer WithPolicyFlags content.
        let entry = cache.get("rustfmt").expect("entry exists");
        assert!(
            entry.verify(&vk, "abc123", "rustfmt").is_err(),
            "tampered new-format entry must fail signature verification"
        );

        // check_reuse must deny with signature_invalid.
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(!reuse.reusable, "tampered entry must be denied");
        assert_eq!(
            reuse.reason, "signature_invalid",
            "tampered entry must be denied via signature_invalid"
        );

        // Even with --allow-legacy-cache, tampered signature is rejected.
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), true);
        assert!(
            !reuse.reusable,
            "tampered entry must be denied even with --allow-legacy-cache"
        );
        assert_eq!(reuse.reason, "signature_invalid");
    }

    /// BLOCKER regression test 2: Mutating policy flags on a LEGACY-format
    /// signed entry does NOT bypass the policy gate.
    ///
    /// A legacy-format entry was signed with `WithoutPolicyFlags`. An
    /// attacker who sets `rfc0028_receipt_bound=true` in the YAML of a
    /// legacy entry cannot bypass the policy gate because:
    /// 1. `WithPolicyFlags` verification fails (signature was over shorter
    ///    content).
    /// 2. `WithoutPolicyFlags` verification succeeds (flags not in signed
    ///    content).
    /// 3. `check_reuse` sees `WithoutPolicyFlags` format and forces effective
    ///    flags to `false`, ignoring the tampered YAML values.
    #[test]
    fn tamper_legacy_entry_policy_flags_still_denied() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();

        // Create a legacy-format entry with rfc0028=false, rfc0029=false.
        let mut cache = make_legacy_signed_cache_with_bindings(&signer, false, false);

        // Tamper: attacker sets rfc0028=true, rfc0029=true in the YAML
        // hoping to bypass the policy gate.
        if let Some(entry) = cache.gates.get_mut("rustfmt") {
            entry.rfc0028_receipt_bound = true;
            entry.rfc0029_receipt_bound = true;
        }

        // Signature still verifies (via legacy format fallback).
        let entry = cache.get("rustfmt").expect("entry exists");
        let format = entry.verify(&vk, "abc123", "rustfmt").expect("must verify");
        assert_eq!(
            format,
            CanonicalBytesFormat::WithoutPolicyFlags,
            "tampered legacy entry must verify as WithoutPolicyFlags (flags not signed)"
        );

        // check_reuse MUST deny: format is WithoutPolicyFlags, so effective
        // flags are forced to false regardless of YAML values.
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse.reusable,
            "tampered legacy entry must be denied — effective flags forced to false"
        );
        assert_eq!(
            reuse.reason, "receipt_binding_missing",
            "denial must come from policy gate, not signature gate"
        );
    }

    /// BLOCKER regression test 3: New-format entry with flags=true roundtrips
    /// correctly — signature verifies as `WithPolicyFlags` and policy allows
    /// hit.
    #[test]
    fn roundtrip_new_entry_with_bindings_passes() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();

        // Create a new-format entry with both bindings = true (normal flow).
        let cache = make_signed_cache(&signer);

        // Verify the format is WithPolicyFlags.
        let entry = cache.get("rustfmt").expect("entry exists");
        let format = entry.verify(&vk, "abc123", "rustfmt").expect("must verify");
        assert_eq!(
            format,
            CanonicalBytesFormat::WithPolicyFlags,
            "new entry must verify as WithPolicyFlags"
        );

        // check_reuse must pass: signature valid, policy flags trusted
        // (signed), both bindings are true.
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(reuse.reusable, "new entry with bindings must be accepted");
        assert_eq!(reuse.reason, "attestation_match");

        // YAML roundtrip must preserve the signature and policy flags.
        let yaml = serde_yaml::to_string(&cache).expect("serialize");
        let restored: GateCache = serde_yaml::from_str(&yaml).expect("deserialize");

        let reuse = restored.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            reuse.reusable,
            "new entry must pass check_reuse after YAML roundtrip"
        );
        assert_eq!(reuse.reason, "attestation_match");
    }

    /// BLOCKER regression test 4: Legacy-format entry without flags roundtrips
    /// correctly — signature verifies as `WithoutPolicyFlags` and policy
    /// denies.
    #[test]
    fn roundtrip_legacy_entry_without_bindings_denied() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();

        // Create a legacy-format entry (signed without policy flags).
        let cache = make_legacy_signed_cache_with_bindings(&signer, false, false);

        // Verify the format is WithoutPolicyFlags.
        let entry = cache.get("rustfmt").expect("entry exists");
        let format = entry.verify(&vk, "abc123", "rustfmt").expect("must verify");
        assert_eq!(
            format,
            CanonicalBytesFormat::WithoutPolicyFlags,
            "legacy entry must verify as WithoutPolicyFlags"
        );

        // check_reuse must deny: format is WithoutPolicyFlags, effective
        // flags forced to false.
        let reuse = cache.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse.reusable,
            "legacy entry without bindings must be denied"
        );
        assert_eq!(reuse.reason, "receipt_binding_missing");

        // YAML roundtrip must preserve the legacy signature behavior.
        let yaml = serde_yaml::to_string(&cache).expect("serialize");
        let restored: GateCache = serde_yaml::from_str(&yaml).expect("deserialize");

        let reuse = restored.check_reuse("rustfmt", Some("digest-1"), true, Some(&vk), false);
        assert!(
            !reuse.reusable,
            "legacy entry must still be denied after YAML roundtrip"
        );
        assert_eq!(reuse.reason, "receipt_binding_missing");
    }

    // --- TCK-00540 BLOCKER fix: canonical_bytes structural tests ---

    /// `WithoutPolicyFlags` format produces identical output regardless
    /// of the policy flag values (backward-compatible behavior).
    #[test]
    fn canonical_bytes_without_policy_flags_ignores_flag_values() {
        let mut entry = CachedGateResult {
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
            legacy_cache_override: false,
        };

        let bytes_bound =
            entry.canonical_bytes("sha1", "gate1", CanonicalBytesFormat::WithoutPolicyFlags);

        // Flip ALL policy flags.
        entry.rfc0028_receipt_bound = false;
        entry.rfc0029_receipt_bound = false;
        entry.legacy_cache_override = true;

        let bytes_unbound =
            entry.canonical_bytes("sha1", "gate1", CanonicalBytesFormat::WithoutPolicyFlags);

        assert_eq!(
            bytes_bound, bytes_unbound,
            "WithoutPolicyFlags canonical_bytes must be identical regardless of flag values"
        );
    }

    /// `WithPolicyFlags` format produces DIFFERENT output when policy flag
    /// values differ. This is the tamper-detection mechanism.
    #[test]
    fn canonical_bytes_with_policy_flags_differs_on_flag_change() {
        let mut entry = CachedGateResult {
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
            legacy_cache_override: false,
        };

        let bytes_true =
            entry.canonical_bytes("sha1", "gate1", CanonicalBytesFormat::WithPolicyFlags);

        // Flip policy flags.
        entry.rfc0028_receipt_bound = false;
        entry.rfc0029_receipt_bound = false;
        entry.legacy_cache_override = true;

        let bytes_false =
            entry.canonical_bytes("sha1", "gate1", CanonicalBytesFormat::WithPolicyFlags);

        assert_ne!(
            bytes_true, bytes_false,
            "WithPolicyFlags canonical_bytes must differ when flag values change"
        );
    }

    /// `WithPolicyFlags` output is strictly longer than `WithoutPolicyFlags`
    /// output (3 extra bytes for the 3 boolean flags). This ensures the two
    /// formats cannot collide.
    #[test]
    fn canonical_bytes_with_policy_flags_is_longer() {
        let entry = CachedGateResult {
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
            legacy_cache_override: false,
        };

        let bytes_with =
            entry.canonical_bytes("sha1", "gate1", CanonicalBytesFormat::WithPolicyFlags);
        let bytes_without =
            entry.canonical_bytes("sha1", "gate1", CanonicalBytesFormat::WithoutPolicyFlags);

        assert_eq!(
            bytes_with.len(),
            bytes_without.len() + 3,
            "WithPolicyFlags must be exactly 3 bytes longer than WithoutPolicyFlags"
        );
    }

    /// Dual-format verify: new-format entry verifies as `WithPolicyFlags`.
    #[test]
    fn verify_returns_with_policy_flags_for_new_entry() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let cache = make_signed_cache(&signer);

        let entry = cache.get("rustfmt").expect("entry exists");
        let format = entry.verify(&vk, "abc123", "rustfmt").expect("must verify");
        assert_eq!(format, CanonicalBytesFormat::WithPolicyFlags);
    }

    /// Dual-format verify: legacy-format entry verifies as
    /// `WithoutPolicyFlags`.
    #[test]
    fn verify_returns_without_policy_flags_for_legacy_entry() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let cache = make_legacy_signed_cache_with_bindings(&signer, false, false);

        let entry = cache.get("rustfmt").expect("entry exists");
        let format = entry.verify(&vk, "abc123", "rustfmt").expect("must verify");
        assert_eq!(format, CanonicalBytesFormat::WithoutPolicyFlags);
    }

    /// `mark_legacy_override` followed by `sign_all` creates a valid
    /// new-format signature that covers the override flags. Verifying
    /// after mark+sign returns `WithPolicyFlags`.
    #[test]
    fn mark_then_sign_produces_valid_new_format_signature() {
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
        // Production flow: mark BEFORE sign.
        cache.mark_legacy_override("rustfmt");
        cache.sign_all(&signer);

        let entry = cache.get("rustfmt").expect("entry exists");
        let format = entry
            .verify(&vk, "abc123", "rustfmt")
            .expect("must verify after mark+sign");
        assert_eq!(
            format,
            CanonicalBytesFormat::WithPolicyFlags,
            "mark+sign must produce WithPolicyFlags signature"
        );
    }
}
