//! Shared key derivation helpers for TOCTOU-verified tool content.

use std::path::Path;

use apm2_core::context::{ManifestError, normalize_path};

/// Derives the canonical verified-content key for a path.
///
/// Keys are manifest-style normalized paths (leading `/`, no `.` or `..`).
pub(super) fn normalized_verified_content_key(path: &Path) -> Result<String, ManifestError> {
    normalize_path(path.to_string_lossy().as_ref())
}

/// Derives a workspace-relative verified-content key when the path is inside
/// `canonical_root`.
pub(super) fn normalized_verified_content_workspace_key(
    path: &Path,
    canonical_root: &Path,
) -> Result<Option<String>, ManifestError> {
    let Ok(relative) = path.strip_prefix(canonical_root) else {
        return Ok(None);
    };

    if relative.as_os_str().is_empty() {
        return Ok(Some("/".to_string()));
    }

    normalized_verified_content_key(relative).map(Some)
}

/// Returns lookup keys in deterministic precedence order.
///
/// Workspace-relative keys are preferred so handler lookups align with broker
/// inserts derived from relative request paths. Absolute keys remain as
/// fallback for compatibility with existing absolute-path manifests/tests.
pub(super) fn normalized_verified_content_lookup_keys(
    path: &Path,
    canonical_root: &Path,
) -> Result<Vec<String>, ManifestError> {
    let mut keys = Vec::with_capacity(2);

    if let Some(relative_key) = normalized_verified_content_workspace_key(path, canonical_root)? {
        keys.push(relative_key);
    }

    let absolute_key = normalized_verified_content_key(path)?;
    if !keys.iter().any(|existing| existing == &absolute_key) {
        keys.push(absolute_key);
    }

    Ok(keys)
}
