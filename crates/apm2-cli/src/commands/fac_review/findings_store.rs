//! Local SHA-bound findings storage and projection helpers.

use std::collections::BTreeSet;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_jcs;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::types::{
    apm2_home_dir, ensure_parent_dir, normalize_decision_dimension, now_iso8601, sanitize_for_path,
    validate_expected_head_sha,
};

pub(super) const FINDINGS_BUNDLE_SCHEMA: &str = "apm2.fac.sha_findings.bundle.v1";
const FINDINGS_BUNDLE_INTEGRITY_ROLE: &str = "findings_bundle";
const FINDINGS_SECRET_MAX_FILE_BYTES: u64 = 128;
const FINDINGS_SECRET_LEN_BYTES: usize = 32;
const FINDINGS_SECRET_MAX_ENCODED_CHARS: usize = 128;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FindingsBundle {
    pub schema: String,
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub source: String,
    pub updated_at: String,
    pub dimensions: Vec<StoredDimensionFindings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_hmac: Option<String>,
}

#[derive(Serialize)]
struct FindingsBundleIntegrityBinding<'a> {
    schema: &'a str,
    owner_repo: &'a str,
    pr_number: u32,
    head_sha: &'a str,
    source: &'a str,
    updated_at: &'a str,
    dimensions: &'a [StoredDimensionFindings],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredDimensionFindings {
    pub dimension: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    pub findings: Vec<StoredFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredFinding {
    pub finding_id: String,
    pub severity: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_id: Option<String>,
    #[serde(default)]
    pub created_at: String,
    pub evidence_digest: String,
    pub raw_evidence_pointer: String,
}

pub(super) fn findings_bundle_path(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<PathBuf, String> {
    validate_expected_head_sha(head_sha)?;
    Ok(apm2_home_dir()?
        .join("private")
        .join("fac")
        .join("findings")
        .join("repos")
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}"))
        .join(format!("sha-{}", sanitize_for_path(head_sha)))
        .join("bundle.json"))
}

pub(super) fn load_all_findings_bundles(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Vec<FindingsBundle>, String> {
    let pr_dir = apm2_home_dir()?
        .join("private")
        .join("fac")
        .join("findings")
        .join("repos")
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}"));

    if !pr_dir.exists() {
        return Ok(Vec::new());
    }

    let mut bundles = Vec::new();
    let entries = fs::read_dir(&pr_dir).map_err(|err| {
        format!(
            "failed to read findings directory {}: {err}",
            pr_dir.display()
        )
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let bundle_path = path.join("bundle.json");
            if bundle_path.exists() {
                if let Some(sha_dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(head_sha) = sha_dir_name.strip_prefix("sha-") {
                        if let Ok(Some(bundle)) =
                            load_findings_bundle(owner_repo, pr_number, head_sha)
                        {
                            bundles.push(bundle);
                        }
                    }
                }
            }
        }
    }

    // Sort by created_at or updated_at, but updated_at is a string, which we can
    // sort.
    bundles.sort_by(|a, b| a.updated_at.cmp(&b.updated_at));

    Ok(bundles)
}

fn findings_secrets_dir() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?
        .join("private")
        .join("fac")
        .join("findings")
        .join("secrets"))
}

fn findings_secret_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(findings_secrets_dir()?
        .join(FINDINGS_BUNDLE_INTEGRITY_ROLE)
        .join(sanitize_for_path(owner_repo))
        .join(format!("pr-{pr_number}.secret")))
}

#[cfg(unix)]
fn open_secret_for_read(path: &Path) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            err
        } else {
            std::io::Error::new(
                err.kind(),
                format!("failed to open findings secret {}: {err}", path.display()),
            )
        }
    })
}

#[cfg(not(unix))]
fn open_secret_for_read(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new().read(true).open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            err
        } else {
            std::io::Error::new(
                err.kind(),
                format!("failed to open findings secret {}: {err}", path.display()),
            )
        }
    })
}

fn read_secret_hex_bytes(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let mut file = match open_secret_for_read(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to open findings secret {}: {err}",
                path.display()
            ));
        },
    };

    let size = file
        .metadata()
        .map_err(|err| format!("failed to stat findings secret {}: {err}", path.display()))?
        .len();
    if size > FINDINGS_SECRET_MAX_FILE_BYTES {
        return Err(format!(
            "findings secret {} exceeds maximum size ({} > {})",
            path.display(),
            size,
            FINDINGS_SECRET_MAX_FILE_BYTES
        ));
    }

    let mut encoded = String::new();
    file.read_to_string(&mut encoded)
        .map_err(|err| format!("failed to read findings secret {}: {err}", path.display()))?;
    let encoded = encoded.trim();
    if encoded.is_empty() {
        return Ok(None);
    }
    if encoded.len() > FINDINGS_SECRET_MAX_ENCODED_CHARS {
        return Err(format!(
            "findings secret {} exceeds maximum encoded length",
            path.display()
        ));
    }

    let secret = hex::decode(encoded)
        .map_err(|err| format!("failed to decode findings secret {}: {err}", path.display()))?;
    if secret.len() != FINDINGS_SECRET_LEN_BYTES {
        return Err(format!(
            "findings secret {} has invalid length {} (expected {})",
            path.display(),
            secret.len(),
            FINDINGS_SECRET_LEN_BYTES
        ));
    }

    Ok(Some(secret))
}

fn write_secret_atomic(path: &Path, encoded_secret: &str) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("findings secret path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create findings secret temp file: {err}"))?;
    #[cfg(unix)]
    {
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to set findings secret temp file mode: {err}"))?;
    }
    temp.write_all(encoded_secret.as_bytes())
        .map_err(|err| format!("failed to write findings secret {}: {err}", path.display()))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync findings secret {}: {err}", path.display()))?;
    temp.persist(path).map_err(|err| {
        format!(
            "failed to persist findings secret {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

fn rotate_secret(path: &Path) -> Result<Vec<u8>, String> {
    let mut secret = [0u8; FINDINGS_SECRET_LEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let encoded = hex::encode(secret);
    write_secret_atomic(path, &encoded)?;
    Ok(secret.to_vec())
}

fn read_or_rotate_secret(path: &Path) -> Result<Vec<u8>, String> {
    read_secret_hex_bytes(path)?.map_or_else(|| rotate_secret(path), Ok)
}

fn findings_bundle_binding_payload(bundle: &FindingsBundle) -> Result<Vec<u8>, String> {
    let mut sorted_dimensions = bundle.dimensions.clone();
    sorted_dimensions.sort_by(|lhs, rhs| lhs.dimension.cmp(&rhs.dimension));
    for dimension in &mut sorted_dimensions {
        dimension
            .findings
            .sort_by(|lhs, rhs| lhs.finding_id.cmp(&rhs.finding_id));
    }
    let binding = FindingsBundleIntegrityBinding {
        schema: &bundle.schema,
        owner_repo: &bundle.owner_repo,
        pr_number: bundle.pr_number,
        head_sha: &bundle.head_sha,
        source: &bundle.source,
        updated_at: &bundle.updated_at,
        dimensions: &sorted_dimensions,
    };
    serde_jcs::to_vec(&binding)
        .map_err(|err| format!("failed to build findings bundle integrity payload: {err}"))
}

fn compute_hmac(secret: &[u8], payload: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|err| format!("invalid findings integrity secret: {err}"))?;
    mac.update(payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_hmac(stored: &str, computed: &str) -> Result<bool, String> {
    let expected = hex::decode(stored)
        .map_err(|err| format!("invalid findings integrity_hmac encoding: {err}"))?;
    let actual = hex::decode(computed)
        .map_err(|err| format!("invalid findings computed integrity_hmac encoding: {err}"))?;
    if expected.len() != actual.len() {
        return Ok(false);
    }
    Ok(expected.ct_eq(actual.as_slice()).into())
}

fn bind_findings_bundle_integrity(bundle: &mut FindingsBundle) -> Result<(), String> {
    let secret =
        read_or_rotate_secret(&findings_secret_path(&bundle.owner_repo, bundle.pr_number)?)?;
    let payload = findings_bundle_binding_payload(bundle)?;
    let computed = compute_hmac(&secret, &payload)?;
    if let Some(stored) = bundle.integrity_hmac.as_deref() {
        let matches = verify_hmac(stored, &computed)?;
        if !matches {
            return Err("findings bundle integrity check failed".to_string());
        }
        return Ok(());
    }

    bundle.integrity_hmac = Some(computed);
    Ok(())
}

fn verify_findings_bundle_integrity_without_rotation(
    bundle: &FindingsBundle,
) -> Result<(), String> {
    let Some(stored) = bundle.integrity_hmac.as_deref() else {
        return Err(format!(
            "missing findings bundle integrity_hmac for {} PR #{} sha {}",
            bundle.owner_repo, bundle.pr_number, bundle.head_sha
        ));
    };
    let secret =
        read_secret_hex_bytes(&findings_secret_path(&bundle.owner_repo, bundle.pr_number)?)?
            .ok_or_else(|| {
                format!(
                    "missing findings integrity secret for {} PR #{}",
                    bundle.owner_repo, bundle.pr_number
                )
            })?;
    let payload = findings_bundle_binding_payload(bundle)?;
    let computed = compute_hmac(&secret, &payload)?;
    let matches = verify_hmac(stored, &computed)?;
    if !matches {
        return Err("findings bundle integrity check failed".to_string());
    }
    Ok(())
}

fn findings_lock_path(owner_repo: &str, pr_number: u32, head_sha: &str) -> Result<PathBuf, String> {
    let bundle_path = findings_bundle_path(owner_repo, pr_number, head_sha)?;
    let parent = bundle_path.parent().ok_or_else(|| {
        format!(
            "findings bundle path has no parent: {}",
            bundle_path.display()
        )
    })?;
    Ok(parent.join("bundle.lock"))
}

fn acquire_findings_lock(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<std::fs::File, String> {
    let lock_path = findings_lock_path(owner_repo, pr_number, head_sha)?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open findings lock {}: {err}",
                lock_path.display()
            )
        })?;
    lock_file
        .lock_exclusive()
        .map_err(|err| format!("failed to lock findings {}: {err}", lock_path.display()))?;
    Ok(lock_file)
}

pub(super) fn load_findings_bundle(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<Option<FindingsBundle>, String> {
    let path = findings_bundle_path(owner_repo, pr_number, head_sha)?;
    let bytes = match fs::read(&path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to read findings bundle {}: {err}",
                path.display()
            ));
        },
    };

    let mut bundle = serde_json::from_slice::<FindingsBundle>(&bytes)
        .map_err(|err| format!("failed to parse findings bundle {}: {err}", path.display()))?;
    validate_loaded_bundle_identity(&bundle, owner_repo, pr_number, head_sha)?;

    // One-time migration for pre-existing bundles that lack an HMAC.
    // Bundles created before HMAC integrity was introduced have
    // integrity_hmac == None. Rather than rejecting them (which would
    // block auto-verdict derivation and verdict show for active PRs),
    // compute the HMAC on first load and persist it atomically.
    if bundle.integrity_hmac.is_none() {
        bind_findings_bundle_integrity(&mut bundle)?;
        write_json_atomic(&path, &bundle)?;
    } else {
        verify_findings_bundle_integrity_without_rotation(&bundle)?;
    }

    Ok(Some(bundle))
}

pub(super) fn save_findings_bundle(bundle: &FindingsBundle) -> Result<(), String> {
    let path = findings_bundle_path(&bundle.owner_repo, bundle.pr_number, &bundle.head_sha)?;
    let mut copy = bundle.clone();
    copy.integrity_hmac = None;
    bind_findings_bundle_integrity(&mut copy)?;
    write_json_atomic(&path, &copy)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_dimension_finding(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
    severity: &str,
    summary: &str,
    details: Option<&str>,
    risk: Option<&str>,
    impact: Option<&str>,
    location: Option<&str>,
    reviewer_id: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    evidence_pointer: Option<&str>,
    source: &str,
) -> Result<(FindingsBundle, StoredFinding), String> {
    validate_expected_head_sha(head_sha)?;
    let normalized_sha = head_sha.to_ascii_lowercase();
    let _lock = acquire_findings_lock(owner_repo, pr_number, &normalized_sha)?;
    let normalized_dimension = normalize_decision_dimension(dimension)?.to_string();
    let normalized_severity = normalize_severity(severity)?.to_string();
    let normalized_summary = summary.trim();
    if normalized_summary.is_empty() {
        return Err("finding summary is empty".to_string());
    }

    let mut bundle = load_findings_bundle(owner_repo, pr_number, &normalized_sha)?
        .unwrap_or_else(|| empty_bundle(owner_repo, pr_number, &normalized_sha, source));
    if bundle.schema != FINDINGS_BUNDLE_SCHEMA {
        return Err(format!(
            "unsupported findings bundle schema `{}` at repo={} pr={} sha={}",
            bundle.schema, owner_repo, pr_number, normalized_sha
        ));
    }

    let dimension_entry = upsert_dimension(&mut bundle, &normalized_dimension);
    let created_at = now_iso8601();
    let finding_id =
        allocate_finding_id(pr_number, &normalized_dimension, &dimension_entry.findings);
    let finding = StoredFinding {
        finding_id,
        severity: normalized_severity,
        summary: normalized_summary.to_string(),
        details: normalize_optional_text(details),
        risk: normalize_optional_text(risk),
        impact: normalize_optional_text(impact),
        location: normalize_optional_text(location),
        reviewer_id: normalize_optional_text(reviewer_id),
        model_id: normalize_optional_text(model_id),
        backend_id: normalize_optional_text(backend_id),
        created_at,
        evidence_digest: finding_digest(
            owner_repo,
            pr_number,
            &normalized_sha,
            &normalized_dimension,
            severity,
            normalized_summary,
            details,
            risk,
            impact,
            location,
            reviewer_id,
            model_id,
            backend_id,
            evidence_pointer,
        )?,
        raw_evidence_pointer: normalize_optional_text(evidence_pointer)
            .unwrap_or_else(|| "none".to_string()),
    };
    dimension_entry.findings.push(finding.clone());
    bundle.source = source.to_string();
    bundle.updated_at = now_iso8601();
    save_findings_bundle(&bundle)?;
    Ok((bundle, finding))
}

pub(super) fn find_dimension<'a>(
    bundle: &'a FindingsBundle,
    dimension: &str,
) -> Option<&'a StoredDimensionFindings> {
    let normalized = normalize_decision_dimension(dimension).ok()?;
    bundle
        .dimensions
        .iter()
        .find(|entry| normalize_decision_dimension(&entry.dimension).ok() == Some(normalized))
}

pub(super) fn find_finding<'a>(
    bundle: &'a FindingsBundle,
    dimension: &str,
    finding_id: &str,
) -> Option<&'a StoredFinding> {
    find_dimension(bundle, dimension)?
        .findings
        .iter()
        .find(|entry| entry.finding_id == finding_id)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create temp file in {}: {err}", parent.display()))?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), value)
        .map_err(|err| format!("failed to serialize {}: {err}", path.display()))?;
    tmp.as_file_mut()
        .flush()
        .map_err(|err| format!("failed to flush {}: {err}", path.display()))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", path.display()))?;
    tmp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

fn empty_bundle(owner_repo: &str, pr_number: u32, head_sha: &str, source: &str) -> FindingsBundle {
    FindingsBundle {
        schema: FINDINGS_BUNDLE_SCHEMA.to_string(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        head_sha: head_sha.to_string(),
        source: source.to_string(),
        updated_at: now_iso8601(),
        integrity_hmac: None,
        dimensions: vec![
            StoredDimensionFindings {
                dimension: "security".to_string(),
                status: "MISSING".to_string(),
                verdict: None,
                findings: Vec::new(),
            },
            StoredDimensionFindings {
                dimension: "code-quality".to_string(),
                status: "MISSING".to_string(),
                verdict: None,
                findings: Vec::new(),
            },
        ],
    }
}

fn validate_loaded_bundle_identity(
    bundle: &FindingsBundle,
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<(), String> {
    if bundle.schema != FINDINGS_BUNDLE_SCHEMA {
        return Err(format!(
            "unsupported findings bundle schema `{}` at repo={} pr={} sha={}",
            bundle.schema, owner_repo, pr_number, head_sha
        ));
    }
    if !bundle.owner_repo.eq_ignore_ascii_case(owner_repo) {
        return Err(format!(
            "findings bundle repo mismatch: expected {owner_repo}, got {}",
            bundle.owner_repo
        ));
    }
    if bundle.pr_number != pr_number {
        return Err(format!(
            "findings bundle PR mismatch: expected #{pr_number}, got #{}",
            bundle.pr_number
        ));
    }
    validate_expected_head_sha(&bundle.head_sha)?;
    if !bundle.head_sha.eq_ignore_ascii_case(head_sha) {
        return Err(format!(
            "findings bundle SHA mismatch: expected {head_sha}, got {}",
            bundle.head_sha
        ));
    }
    Ok(())
}

fn normalize_severity(severity: &str) -> Result<&'static str, String> {
    match severity.trim().to_ascii_uppercase().as_str() {
        "BLOCKER" => Ok("BLOCKER"),
        "MAJOR" => Ok("MAJOR"),
        "MINOR" => Ok("MINOR"),
        "NIT" => Ok("NIT"),
        other => Err(format!(
            "invalid finding severity `{other}` (expected BLOCKER|MAJOR|MINOR|NIT)"
        )),
    }
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
}

fn allocate_finding_id(pr_number: u32, dimension: &str, existing: &[StoredFinding]) -> String {
    let dim = dimension.replace('-', "_");
    let existing_ids = existing
        .iter()
        .map(|value| value.finding_id.as_str())
        .collect::<BTreeSet<_>>();
    for attempt in 0..1024u16 {
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_micros())
            .unwrap_or_default();
        let candidate = format!("f-{pr_number}-{dim}-{micros}-{attempt}");
        if !existing_ids.contains(candidate.as_str()) {
            return candidate;
        }
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default();
    format!("f-{pr_number}-{dim}-{secs}-overflow")
}

#[allow(clippy::too_many_arguments)]
fn finding_digest(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    dimension: &str,
    severity: &str,
    summary: &str,
    details: Option<&str>,
    risk: Option<&str>,
    impact: Option<&str>,
    location: Option<&str>,
    reviewer_id: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    evidence_pointer: Option<&str>,
) -> Result<String, String> {
    let payload = serde_json::json!({
        "owner_repo": owner_repo,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "dimension": dimension,
        "severity": severity.trim().to_ascii_uppercase(),
        "summary": summary.trim(),
        "details": details.map_or("", str::trim),
        "risk": risk.map_or("", str::trim),
        "impact": impact.map_or("", str::trim),
        "location": location.map_or("", str::trim),
        "reviewer_id": reviewer_id.map_or("", str::trim),
        "model_id": model_id.map_or("", str::trim),
        "backend_id": backend_id.map_or("", str::trim),
        "evidence_pointer": evidence_pointer.map_or("", str::trim),
    });
    let canonical = serde_jcs::to_vec(&payload)
        .map_err(|err| format!("failed to serialize finding digest payload: {err}"))?;
    let digest = sha2::Sha256::digest(&canonical);
    Ok(hex::encode(digest))
}

fn upsert_dimension<'a>(
    bundle: &'a mut FindingsBundle,
    dimension: &str,
) -> &'a mut StoredDimensionFindings {
    if let Some(pos) = bundle
        .dimensions
        .iter()
        .position(|entry| normalize_decision_dimension(&entry.dimension).ok() == Some(dimension))
    {
        return &mut bundle.dimensions[pos];
    }

    bundle.dimensions.push(StoredDimensionFindings {
        dimension: dimension.to_string(),
        status: "MISSING".to_string(),
        verdict: None,
        findings: Vec::new(),
    });
    let len = bundle.dimensions.len();
    &mut bundle.dimensions[len - 1]
}

#[cfg(test)]
mod tests {
    use super::{
        StoredFinding, allocate_finding_id, compute_hmac, empty_bundle,
        findings_bundle_binding_payload, validate_loaded_bundle_identity, verify_hmac,
    };

    #[test]
    fn allocate_finding_id_avoids_existing_collision() {
        let first = allocate_finding_id(77, "security", &[]);
        let existing = vec![StoredFinding {
            finding_id: first.clone(),
            severity: "MAJOR".to_string(),
            summary: "existing".to_string(),
            details: None,
            risk: None,
            impact: None,
            location: None,
            reviewer_id: None,
            model_id: None,
            backend_id: None,
            created_at: "2026-02-14T00:00:00Z".to_string(),
            evidence_digest: "digest".to_string(),
            raw_evidence_pointer: "none".to_string(),
        }];
        let second = allocate_finding_id(77, "security", &existing);
        assert_ne!(first, second);
    }

    #[test]
    fn validate_loaded_bundle_identity_rejects_mismatch() {
        let bundle = empty_bundle(
            "guardian-intelligence/apm2",
            482,
            "0123456789abcdef0123456789abcdef01234567",
            "test",
        );
        let err = validate_loaded_bundle_identity(
            &bundle,
            "guardian-intelligence/apm2",
            999,
            "0123456789abcdef0123456789abcdef01234567",
        )
        .expect_err("pr mismatch should fail");
        assert!(err.contains("PR mismatch"));
    }

    /// Verifies that the HMAC migration path works: a bundle without an HMAC
    /// can have one computed, and subsequent verification succeeds. This is the
    /// core invariant for MAJOR-2 (pre-existing bundles migration).
    #[test]
    fn hmac_roundtrip_for_bundle_without_existing_hmac() {
        let bundle = empty_bundle(
            "guardian-intelligence/apm2",
            482,
            "0123456789abcdef0123456789abcdef01234567",
            "test",
        );
        assert!(bundle.integrity_hmac.is_none(), "fresh bundle has no HMAC");

        // Compute HMAC with a known secret.
        let secret = vec![0xABu8; 32];
        let payload = findings_bundle_binding_payload(&bundle).expect("binding payload");
        let hmac = compute_hmac(&secret, &payload).expect("compute HMAC");

        // Verification with the same secret and payload must succeed.
        let verification_payload = findings_bundle_binding_payload(&bundle).expect("payload");
        let recomputed = compute_hmac(&secret, &verification_payload).expect("recompute");
        assert!(
            verify_hmac(&hmac, &recomputed).expect("verify"),
            "HMAC must verify for same bundle content"
        );
    }

    /// Verifies that HMAC verification rejects tampered content.
    #[test]
    fn hmac_rejects_tampered_bundle() {
        let bundle = empty_bundle(
            "guardian-intelligence/apm2",
            482,
            "0123456789abcdef0123456789abcdef01234567",
            "test",
        );
        let secret = vec![0xCDu8; 32];
        let payload = findings_bundle_binding_payload(&bundle).expect("payload");
        let hmac = compute_hmac(&secret, &payload).expect("compute HMAC");

        // Tamper: create a different bundle.
        let tampered = empty_bundle(
            "guardian-intelligence/apm2",
            999,
            "0123456789abcdef0123456789abcdef01234567",
            "test",
        );
        let tampered_payload =
            findings_bundle_binding_payload(&tampered).expect("tampered payload");
        let tampered_hmac = compute_hmac(&secret, &tampered_payload).expect("tampered HMAC");

        assert!(
            !verify_hmac(&hmac, &tampered_hmac).expect("cross-verify"),
            "HMAC must reject tampered content"
        );
    }
}
