use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use {blake3, serde_json};

use crate::determinism::canonicalize_json;

pub const GC_RECEIPT_SCHEMA: &str = "apm2.fac.gc_receipt.v1";
pub const MAX_GC_ACTIONS: usize = 4096;
pub const MAX_GC_RECEIPT_SIZE: usize = 1_048_576;
pub const DEFAULT_MIN_FREE_BYTES: u64 = 1_073_741_824;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub timestamp_secs: u64,
    pub before_free_bytes: u64,
    pub after_free_bytes: u64,
    pub min_free_threshold: u64,
    pub actions: Vec<GcAction>,
    pub errors: Vec<GcError>,
    pub content_hash: String,
}

impl GcReceiptV1 {
    /// Validate this receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != GC_RECEIPT_SCHEMA {
            return Err("invalid schema".to_string());
        }
        if self.receipt_id.trim().is_empty() {
            return Err("receipt_id must not be empty".to_string());
        }
        if self.timestamp_secs == 0 {
            return Err("timestamp_secs must be positive".to_string());
        }
        if self.min_free_threshold == 0 {
            return Err("min_free_threshold must be greater than zero".to_string());
        }
        if self.actions.len() > MAX_GC_ACTIONS {
            return Err("too many actions".to_string());
        }
        if self.errors.len() > MAX_GC_ACTIONS {
            return Err("too many errors".to_string());
        }

        for action in &self.actions {
            if action.target_path.trim().is_empty() {
                return Err("action target_path must not be empty".to_string());
            }
        }
        Ok(())
    }

    /// Serialize this receipt with canonical JSON ordering.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let json = serde_json::to_string(self)
            .map_err(|error| format!("failed to serialize gc receipt: {error}"))?;
        canonicalize_json(&json)
            .map_err(|error| format!("failed to canonicalize gc receipt: {error}"))
            .map(String::into_bytes)
    }

    /// Compute the receipt content hash over canonicalized JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON canonicalization fails.
    pub fn compute_content_hash(&self) -> Result<String, String> {
        let mut copy = self.clone();
        copy.content_hash = String::new();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.fac.gc_receipt.v1\0");
        let canonical = copy.canonical_bytes()?;
        hasher.update(&canonical);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcAction {
    pub target_path: String,
    pub action_kind: GcActionKind,
    pub bytes_freed: u64,
    pub files_deleted: u64,
    pub dirs_deleted: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcActionKind {
    LaneTarget,
    LaneLog,
    GateCache,
    BlobPrune,
    QuarantinePrune,
    DeniedPrune,
    CargoCache,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcError {
    pub target_path: String,
    pub reason: String,
}

/// Persist the receipt into `receipts_dir` and return the created path.
///
/// # Errors
///
/// Returns `Err` if writing or validation fails.
pub fn persist_gc_receipt(
    receipts_dir: &Path,
    mut receipt: GcReceiptV1,
) -> Result<PathBuf, String> {
    if receipt.schema != GC_RECEIPT_SCHEMA {
        receipt.schema = GC_RECEIPT_SCHEMA.to_string();
    }
    if receipt.receipt_id.trim().is_empty() {
        let now = current_wall_clock_secs();
        receipt.receipt_id = now.to_string();
    }
    if receipt.timestamp_secs == 0 {
        receipt.timestamp_secs = current_wall_clock_secs();
    }
    let content_hash = receipt.compute_content_hash()?;
    receipt.content_hash.clone_from(&content_hash);
    receipt.validate()?;

    let bytes = receipt.canonical_bytes()?;
    if bytes.len() > MAX_GC_RECEIPT_SIZE {
        return Err("gc receipt exceeds max size".to_string());
    }

    let mut path = receipts_dir.to_path_buf();
    if content_hash.len() < 4 {
        return Err("content hash is malformed".to_string());
    }
    let prefix = &content_hash[..2];
    let suffix = &content_hash[2..];
    path.push(prefix);
    std::fs::create_dir_all(&path)
        .map_err(|error| format!("failed to create receipt dir: {error}"))?;
    path.push(format!("{suffix}.json"));

    // Atomic write.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes).map_err(|error| format!("failed to write receipt: {error}"))?;
    std::fs::rename(&tmp, &path).map_err(|error| format!("failed to persist receipt: {error}"))?;
    Ok(path)
}

// SECURITY JUSTIFICATION (CTR-2501): GC receipt timestamps use wall-clock
// time because receipt creation is an operational maintenance task, not a
// coordinated consensus operation.
#[allow(clippy::disallowed_methods)]
fn current_wall_clock_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gc_receipt_content_hash_deterministic() {
        let receipt_a = GcReceiptV1 {
            schema: GC_RECEIPT_SCHEMA.to_string(),
            receipt_id: "id-a".to_string(),
            timestamp_secs: 1,
            before_free_bytes: 4,
            after_free_bytes: 8,
            min_free_threshold: 1,
            actions: vec![],
            errors: vec![],
            content_hash: String::new(),
        };
        let receipt_b = receipt_a.clone();
        assert_eq!(
            receipt_a.compute_content_hash().expect("hash"),
            receipt_b.compute_content_hash().expect("hash")
        );
    }

    #[test]
    fn test_gc_receipt_roundtrip() {
        let mut receipt = GcReceiptV1 {
            schema: GC_RECEIPT_SCHEMA.to_string(),
            receipt_id: "id-roundtrip".to_string(),
            timestamp_secs: 2,
            before_free_bytes: 10,
            after_free_bytes: 20,
            min_free_threshold: 5,
            actions: vec![GcAction {
                target_path: "/tmp/test".to_string(),
                action_kind: GcActionKind::LaneLog,
                bytes_freed: 7,
                files_deleted: 3,
                dirs_deleted: 1,
            }],
            errors: vec![GcError {
                target_path: "/tmp/err".to_string(),
                reason: "boom".to_string(),
            }],
            content_hash: String::new(),
        };

        let content_hash = receipt.compute_content_hash().expect("hash");
        receipt.content_hash = content_hash.clone();

        let bytes = serde_json::to_vec(&receipt).expect("serialize");
        let decoded: GcReceiptV1 = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded.content_hash, content_hash);
        assert_eq!(decoded.actions.len(), 1);
        assert_eq!(decoded.errors.len(), 1);
    }

    #[test]
    fn test_gc_action_kind_serializes_snake_case() {
        let v = serde_json::to_string(&GcActionKind::QuarantinePrune).expect("serialize");
        assert_eq!(v, "\"quarantine_prune\"");
        let denied = serde_json::to_string(&GcActionKind::DeniedPrune).expect("serialize");
        assert_eq!(denied, "\"denied_prune\"");
        let blob = serde_json::to_string(&GcActionKind::BlobPrune).expect("serialize");
        assert_eq!(blob, "\"blob_prune\"");
    }
}
