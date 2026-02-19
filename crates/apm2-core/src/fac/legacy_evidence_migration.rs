// AGENT-AUTHORED (TCK-00589)
//! Legacy evidence log deprecation: one-time migration helper.
//!
//! Moves files from the deprecated `private/fac/evidence/` directory into
//! `private/fac/legacy/` and emits a migration receipt under
//! `private/fac/receipts/`. The legacy evidence path is no longer written
//! to by any production code path; this module provides the migration
//! bridge for existing installations.
//!
//! # Directory Layout (post-migration)
//!
//! ```text
//! $APM2_HOME/private/fac/legacy/          # migrated files land here
//! $APM2_HOME/private/fac/receipts/        # migration receipt persisted here
//! $APM2_HOME/private/fac/evidence/        # removed after migration
//! ```
//!
//! # Invariants
//!
//! - [INV-LEM-001] Migration is idempotent: re-running after completion is a
//!   no-op that returns the "already migrated" receipt.
//! - [INV-LEM-002] Files are moved via `fs::rename()` (atomic on same
//!   filesystem). Cross-device moves fall back to copy-then-remove.
//! - [INV-LEM-003] The legacy `evidence/` directory is removed only after all
//!   files have been successfully moved.
//! - [INV-LEM-004] In-memory collections are bounded by `MAX_LEGACY_FILES`.
//! - [INV-LEM-005] Symlink entries are skipped (fail-closed).
//! - [INV-LEM-006] Directory entries are skipped (only regular files are
//!   migrated).
//! - [INV-LEM-007] Non-regular file types (FIFOs, sockets, device nodes) are
//!   rejected with a deterministic error.
//! - [INV-LEM-008] `read_dir` failures on an existing evidence directory are
//!   propagated as `LaneError`, not silently skipped.

use std::path::{Path, PathBuf};
use std::{fs, io};

use serde::{Deserialize, Serialize};

use super::lane::{LaneError, atomic_write, create_dir_restricted};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const MIGRATION_RECEIPT_SCHEMA: &str = "apm2.fac.legacy_evidence_migration.v1";

/// Hard cap on files processed during migration (INV-LEM-004).
const MAX_LEGACY_FILES: usize = 10_000;

/// Subdirectory name for migrated legacy files.
const LEGACY_DIR: &str = "legacy";

/// The deprecated evidence directory name.
const LEGACY_EVIDENCE_DIR: &str = "evidence";

// ─────────────────────────────────────────────────────────────────────────────
// Receipt types
// ─────────────────────────────────────────────────────────────────────────────

/// Receipt emitted after a legacy evidence migration run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Receipt struct — bools are independent flags, not a state machine.
pub struct LegacyEvidenceMigrationReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Number of files moved.
    pub files_moved: usize,
    /// Number of files that failed to move.
    pub files_failed: usize,
    /// Whether the legacy directory was removed after migration.
    pub legacy_dir_removed: bool,
    /// Whether migration was skipped (already completed or nothing to do).
    pub skipped: bool,
    /// Human-readable reason if skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Whether this invocation fully completed the migration. `false` when
    /// the legacy directory contained more entries than `MAX_LEGACY_FILES`
    /// and a subsequent invocation is required to finish.
    #[serde(default = "default_true")]
    pub is_complete: bool,
    /// Total number of directory entries observed in the legacy evidence
    /// directory (capped at `MAX_LEGACY_FILES + 1` for overflow detection).
    /// When `total_entries_seen > MAX_LEGACY_FILES`, partial migration
    /// occurred and `is_complete` is `false`.
    #[serde(default)]
    pub total_entries_seen: usize,
    /// Whether the migration is settled — all migratable (regular) files
    /// have been processed and no further scans are necessary. When `true`,
    /// callers can skip future migration attempts even if the evidence/
    /// directory still exists (due to non-migratable entries like symlinks
    /// or subdirectories).
    #[serde(default)]
    pub migration_settled: bool,
    /// Individual file migration results (bounded by `MAX_LEGACY_FILES`).
    pub file_results: Vec<FileMigrationResult>,
}

/// Serde default helper — returns `true` for backwards compatibility with
/// receipts that predate the `is_complete` field (those receipts were always
/// single-batch completions).
const fn default_true() -> bool {
    true
}

/// Result of migrating a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMigrationResult {
    /// Original filename (not full path, to avoid leaking directory structure).
    pub filename: String,
    /// Whether the move succeeded.
    pub success: bool,
    /// Error message if the move failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a skipped receipt with the given reason, persist it, and return.
fn skip_receipt(
    fac_root: &Path,
    reason: &str,
    legacy_dir_removed: bool,
) -> Result<LegacyEvidenceMigrationReceiptV1, LaneError> {
    let receipt = LegacyEvidenceMigrationReceiptV1 {
        schema: MIGRATION_RECEIPT_SCHEMA.to_string(),
        files_moved: 0,
        files_failed: 0,
        legacy_dir_removed,
        skipped: true,
        skip_reason: Some(reason.to_string()),
        is_complete: true,
        total_entries_seen: 0,
        migration_settled: true,
        file_results: Vec::new(),
    };
    persist_migration_receipt(fac_root, &receipt)?;
    Ok(receipt)
}

/// Migrate a single entry from `evidence/` to `legacy/`.
fn migrate_entry(entry: &fs::DirEntry, legacy_dir: &Path) -> FileMigrationResult {
    let filename = entry.file_name().to_string_lossy().to_string();

    // Path traversal sanitization: reject filenames that contain path
    // separators or traversal components. This prevents a crafted entry
    // from escaping the `legacy/` destination directory.
    if filename.contains('/') || filename.contains('\\') || filename == ".." || filename == "." {
        return FileMigrationResult {
            filename,
            success: false,
            error: Some("rejected: filename contains path traversal components".to_string()),
        };
    }

    let src_path = entry.path();

    // Skip symlinks (INV-LEM-005) and directories (INV-LEM-006).
    match fs::symlink_metadata(&src_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return FileMigrationResult {
                filename,
                success: false,
                error: Some("skipped: symlink entry".to_string()),
            };
        },
        Ok(meta) if meta.is_dir() => {
            return FileMigrationResult {
                filename,
                success: false,
                error: Some("skipped: directory entries are not migrated".to_string()),
            };
        },
        Err(e) => {
            return FileMigrationResult {
                filename,
                success: false,
                error: Some(format!("cannot stat entry: {e}")),
            };
        },
        Ok(meta) if meta.is_file() => {}, // regular file — proceed
        Ok(_) => {
            // Reject all non-regular file types: FIFOs, sockets, device
            // nodes, etc. Only regular files pass the gate above.
            return FileMigrationResult {
                filename,
                success: false,
                error: Some("skipped: not a regular file".to_string()),
            };
        },
    }

    let dst_path = legacy_dir.join(entry.file_name());
    match move_file(&src_path, &dst_path) {
        Ok(()) => FileMigrationResult {
            filename,
            success: true,
            error: None,
        },
        Err(e) => FileMigrationResult {
            filename,
            success: false,
            error: Some(e.to_string()),
        },
    }
}

/// Move a file from `src` to `dst`. Tries `fs::rename` first (atomic on same
/// filesystem). Falls back to copy-then-remove for cross-device moves.
///
/// # Cross-device fallback (EXDEV)
///
/// The copy-then-remove path is intentionally non-atomic: if the process
/// crashes between `copy` and `remove_file`, the source file remains and
/// the next migration run will retry. This is acceptable for the legacy
/// evidence migration context because:
/// - The files are read-only audit evidence (not actively written).
/// - Duplicate copies in `legacy/` are harmless (content-addressed).
/// - The migration is idempotent and will clean up on the next GC cycle.
fn move_file(src: &Path, dst: &Path) -> Result<(), io::Error> {
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            fs::copy(src, dst)?;
            fs::remove_file(src)?;
            Ok(())
        },
        Err(e) => Err(e),
    }
}

/// Persist the migration receipt under `fac_root/receipts/`.
fn persist_migration_receipt(
    fac_root: &Path,
    receipt: &LegacyEvidenceMigrationReceiptV1,
) -> Result<PathBuf, LaneError> {
    let receipts_dir = fac_root.join("receipts");
    create_dir_restricted(&receipts_dir)?;

    let receipt_bytes =
        serde_json::to_vec_pretty(receipt).map_err(|e| LaneError::Serialization(e.to_string()))?;
    let receipt_hash = blake3::hash(&receipt_bytes);
    let receipt_filename = format!(
        "legacy_evidence_migration_{}.json",
        &receipt_hash.to_hex()[..16]
    );
    let receipt_path = receipts_dir.join(&receipt_filename);
    atomic_write(&receipt_path, &receipt_bytes)?;
    Ok(receipt_path)
}

// ─────────────────────────────────────────────────────────────────────────────
// Migration logic
// ─────────────────────────────────────────────────────────────────────────────

/// Run the one-time legacy evidence migration.
///
/// Moves files from `fac_root/evidence/` to `fac_root/legacy/` and emits a
/// migration receipt under `fac_root/receipts/`.
///
/// # Idempotency (INV-LEM-001)
///
/// - If `fac_root/evidence/` does not exist or is empty, returns a "skipped"
///   receipt.
/// - If `fac_root/legacy/` already contains files, the migration still proceeds
///   for any remaining files in `evidence/`.
///
/// # Errors
///
/// Returns `LaneError` on filesystem errors that prevent the migration from
/// completing.
pub fn migrate_legacy_evidence(
    fac_root: &Path,
) -> Result<LegacyEvidenceMigrationReceiptV1, LaneError> {
    let evidence_dir = fac_root.join(LEGACY_EVIDENCE_DIR);
    let legacy_dir = fac_root.join(LEGACY_DIR);

    // If the legacy evidence directory does not exist, nothing to migrate.
    // No receipt is persisted because there is nothing to record — the
    // directory was never present (or was already removed in a prior run).
    if !evidence_dir.exists() {
        return Ok(LegacyEvidenceMigrationReceiptV1 {
            schema: MIGRATION_RECEIPT_SCHEMA.to_string(),
            files_moved: 0,
            files_failed: 0,
            legacy_dir_removed: false,
            skipped: true,
            skip_reason: Some("legacy evidence directory does not exist".to_string()),
            is_complete: true,
            total_entries_seen: 0,
            migration_settled: true,
            file_results: Vec::new(),
        });
    }

    // Validate evidence_dir is a real directory (not a symlink).
    let is_real_dir = fs::symlink_metadata(&evidence_dir)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if !is_real_dir {
        return skip_receipt(
            fac_root,
            "legacy evidence path is not a directory (possibly a symlink)",
            false,
        );
    }

    // Read directory entries (bounded by MAX_LEGACY_FILES).
    // We read up to MAX_LEGACY_FILES + 1 to detect overflow, then only
    // process the first MAX_LEGACY_FILES entries.
    //
    // Iterator errors from `read_dir` are counted explicitly rather than
    // silently dropped via `filter_map(Result::ok)`, so the receipt
    // accurately reflects whether the scan was complete.
    let mut iterator_errors: usize = 0;
    let rd = fs::read_dir(&evidence_dir).map_err(|e| LaneError::Io {
        context: format!(
            "cannot read legacy evidence directory: {}",
            evidence_dir.display()
        ),
        source: e,
    })?;
    let mut all_entries: Vec<fs::DirEntry> = Vec::new();
    for result in rd {
        if all_entries.len() >= MAX_LEGACY_FILES.saturating_add(1) {
            break;
        }
        match result {
            Ok(entry) => all_entries.push(entry),
            Err(_) => {
                iterator_errors = iterator_errors.saturating_add(1);
            },
        }
    }

    if all_entries.is_empty() && iterator_errors == 0 {
        let removed = fs::remove_dir(&evidence_dir).is_ok();
        return skip_receipt(fac_root, "legacy evidence directory is empty", removed);
    }

    let total_entries_seen = all_entries.len().saturating_add(iterator_errors);
    let has_more = all_entries.len() > MAX_LEGACY_FILES;
    let entries = if has_more {
        &all_entries[..MAX_LEGACY_FILES]
    } else {
        &all_entries[..]
    };

    // Ensure legacy destination and receipts directories exist.
    create_dir_restricted(&legacy_dir)?;
    create_dir_restricted(&fac_root.join("receipts"))?;

    // Migrate each entry.
    let file_results: Vec<FileMigrationResult> = entries
        .iter()
        .map(|e| migrate_entry(e, &legacy_dir))
        .collect();

    let files_moved = file_results.iter().filter(|r| r.success).count();
    // Include iterator errors in files_failed so the receipt accurately
    // reflects whether the directory scan was complete and unimpaired.
    let files_failed = file_results
        .iter()
        .filter(|r| !r.success)
        .count()
        .saturating_add(iterator_errors);

    // `is_complete` means all directory entries have been SEEN (processed or
    // skipped), not that all moves succeeded. When `!has_more` we have
    // enumerated every entry in the directory, so no further iterations are
    // needed — even if some entries failed (symlinks, directories, permission
    // errors). This prevents the caller from looping indefinitely when
    // non-movable entries are present.
    let is_complete = !has_more;

    // Determine if migration is settled: all entries have been scanned
    // and all migratable (regular) files have been processed. When
    // `is_complete` is true, every entry in the directory has been seen.
    // Since `migrate_entry` only moves regular files and deterministically
    // skips non-migratable types (symlinks, dirs, special files), there
    // are no retryable failures — callers can stop scanning.
    let migration_settled = is_complete;

    // Attempt to remove the legacy evidence directory when all entries
    // have been scanned (INV-LEM-003). This covers both the clean case
    // (all files moved, directory is empty) and the settled case (only
    // non-migratable entries remain). `remove_dir` will fail if the
    // directory is not empty, which is fine — the `migration_settled`
    // flag tells callers to stop scanning regardless.
    let legacy_dir_removed = is_complete && fs::remove_dir(&evidence_dir).is_ok();

    let receipt = LegacyEvidenceMigrationReceiptV1 {
        schema: MIGRATION_RECEIPT_SCHEMA.to_string(),
        files_moved,
        files_failed,
        legacy_dir_removed,
        skipped: false,
        skip_reason: None,
        is_complete,
        total_entries_seen,
        migration_settled,
        file_results,
    };

    persist_migration_receipt(fac_root, &receipt)?;
    Ok(receipt)
}

/// Hard cap on re-invocations of `migrate_legacy_evidence` when running
/// migration to completion. Prevents unbounded looping if the directory is
/// being refilled by an external actor.
const MAX_MIGRATION_ITERATIONS: usize = 100;

/// Run legacy evidence migration to completion with bounded iterations.
///
/// Repeatedly calls [`migrate_legacy_evidence`] until the migration reports
/// `is_complete == true` or the iteration cap (`MAX_MIGRATION_ITERATIONS`)
/// is reached. This ensures installations with more than `MAX_LEGACY_FILES`
/// entries are fully migrated across multiple batches.
///
/// Returns the final receipt. If the migration could not complete within the
/// iteration cap, the returned receipt will have `is_complete == false`.
///
/// # Production callsite
///
/// This function is invoked by `apm2 fac gc` before GC planning, so
/// upgraded installations automatically migrate legacy evidence during
/// routine garbage collection.
///
/// # Errors
///
/// Returns `LaneError` on filesystem errors that prevent migration.
pub fn run_migration_to_completion(
    fac_root: &Path,
) -> Result<LegacyEvidenceMigrationReceiptV1, LaneError> {
    let mut last_receipt = migrate_legacy_evidence(fac_root)?;
    let mut iterations = 1usize;

    while !last_receipt.is_complete
        && !last_receipt.skipped
        && iterations < MAX_MIGRATION_ITERATIONS
    {
        last_receipt = migrate_legacy_evidence(fac_root)?;
        iterations = iterations.saturating_add(1);
    }

    Ok(last_receipt)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_fac_root() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        (root, fac_root)
    }

    #[test]
    fn migration_skipped_when_no_evidence_dir() {
        let (_root, fac_root) = setup_fac_root();

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert!(receipt.skipped);
        assert!(receipt.is_complete);
        assert!(receipt.migration_settled);
        assert_eq!(receipt.total_entries_seen, 0);
        assert_eq!(receipt.files_moved, 0);
        assert_eq!(receipt.files_failed, 0);
        assert!(
            receipt
                .skip_reason
                .as_deref()
                .unwrap()
                .contains("does not exist")
        );

        // No receipt should be persisted when evidence dir doesn't exist.
        let receipts_dir = fac_root.join("receipts");
        assert!(
            !receipts_dir.exists(),
            "no receipt directory should be created when evidence dir is absent"
        );
    }

    #[test]
    fn migration_skipped_when_evidence_dir_empty() {
        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert!(receipt.skipped);
        assert_eq!(receipt.files_moved, 0);
        assert!(receipt.legacy_dir_removed);
        assert!(receipt.skip_reason.as_deref().unwrap().contains("empty"));

        // Evidence dir should have been removed.
        assert!(!evidence_dir.exists());
    }

    #[test]
    fn migration_moves_files_to_legacy() {
        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        // Create test files in legacy evidence directory.
        fs::write(evidence_dir.join("lane_init_abc123.json"), b"{}").expect("write file 1");
        fs::write(
            evidence_dir.join("lane_reconcile_def456.json"),
            b"{\"test\":true}",
        )
        .expect("write file 2");

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert!(!receipt.skipped);
        assert_eq!(receipt.files_moved, 2);
        assert_eq!(receipt.files_failed, 0);
        assert!(receipt.legacy_dir_removed);
        assert!(receipt.is_complete);
        assert_eq!(receipt.total_entries_seen, 2);

        // Files should now be in legacy/.
        let legacy_dir = fac_root.join("legacy");
        assert!(legacy_dir.join("lane_init_abc123.json").exists());
        assert!(legacy_dir.join("lane_reconcile_def456.json").exists());

        // Legacy evidence dir should be gone.
        assert!(!evidence_dir.exists());
    }

    #[test]
    fn migration_is_idempotent() {
        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");
        fs::write(evidence_dir.join("test.json"), b"{}").expect("write file");

        let first = migrate_legacy_evidence(&fac_root).expect("first migration");
        assert_eq!(first.files_moved, 1);
        assert!(!first.skipped);
        assert!(first.is_complete);

        // Second run: evidence dir no longer exists.
        let second = migrate_legacy_evidence(&fac_root).expect("second migration");
        assert!(second.skipped);
        assert!(second.is_complete);
        assert_eq!(second.files_moved, 0);
    }

    #[cfg(unix)]
    #[test]
    fn migration_skips_symlinks() {
        use std::os::unix::fs::symlink;

        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        // Create a regular file and a symlink.
        let real_file = evidence_dir.join("real.json");
        fs::write(&real_file, b"{}").expect("write real file");

        let target = fac_root.join("outside_target.json");
        fs::write(&target, b"{}").expect("write target");
        symlink(&target, evidence_dir.join("symlink.json")).expect("create symlink");

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert_eq!(receipt.files_moved, 1);
        assert_eq!(receipt.files_failed, 1);
        assert!(
            !receipt.legacy_dir_removed,
            "dir should not be removed when failures exist"
        );
        // All entries were seen even though one failed — is_complete should be
        // true (we scanned every entry, the symlink is just unmovable).
        assert!(
            receipt.is_complete,
            "migration is complete when all entries have been seen"
        );

        // The real file should be in legacy/.
        let legacy_dir = fac_root.join("legacy");
        assert!(legacy_dir.join("real.json").exists());

        // The symlink should still be in evidence/ (not moved).
        assert!(evidence_dir.join("symlink.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn migration_skips_directories() {
        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        // Create a regular file and a subdirectory.
        fs::write(evidence_dir.join("real.json"), b"{}").expect("write real file");
        fs::create_dir(evidence_dir.join("subdir")).expect("create subdir");

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert_eq!(receipt.files_moved, 1);
        assert_eq!(receipt.files_failed, 1);
        assert!(
            receipt.is_complete,
            "all entries seen even with skipped directory"
        );

        // Verify the directory skip is recorded with correct error message.
        let dir_result = receipt
            .file_results
            .iter()
            .find(|r| r.filename == "subdir")
            .expect("should have result for subdir");
        assert!(!dir_result.success);
        assert!(
            dir_result
                .error
                .as_deref()
                .unwrap()
                .contains("directory entries are not migrated"),
            "error message should indicate directory skip"
        );

        // The real file should be in legacy/.
        let legacy_dir = fac_root.join("legacy");
        assert!(legacy_dir.join("real.json").exists());

        // The subdirectory should still be in evidence/ (not moved).
        assert!(evidence_dir.join("subdir").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn run_migration_to_completion_does_not_loop_on_unmovable_entries() {
        use std::os::unix::fs::symlink;

        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        // Create only a symlink (unmovable) — no regular files.
        let target = fac_root.join("outside_target.json");
        fs::write(&target, b"{}").expect("write target");
        symlink(&target, evidence_dir.join("symlink.json")).expect("create symlink");

        // This should complete in 1 iteration, NOT loop 100 times.
        let receipt = run_migration_to_completion(&fac_root).expect("migrate");
        assert!(
            receipt.is_complete,
            "migration should be complete (all entries seen)"
        );
        assert_eq!(receipt.files_moved, 0);
        assert_eq!(receipt.files_failed, 1);
    }

    #[test]
    fn migration_emits_receipt() {
        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");
        fs::write(evidence_dir.join("test.json"), b"{}").expect("write file");

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert_eq!(receipt.schema, MIGRATION_RECEIPT_SCHEMA);
        assert_eq!(receipt.files_moved, 1);

        // Verify receipt was persisted.
        let receipts_dir = fac_root.join("receipts");
        let receipt_files: Vec<_> = fs::read_dir(&receipts_dir)
            .expect("read")
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("legacy_evidence_migration_")
            })
            .collect();
        assert_eq!(receipt_files.len(), 1);

        // Verify receipt content is valid JSON with new fields.
        let content = fs::read_to_string(receipt_files[0].path()).expect("read receipt");
        let parsed: LegacyEvidenceMigrationReceiptV1 =
            serde_json::from_str(&content).expect("parse receipt");
        assert_eq!(parsed.files_moved, 1);
        assert!(parsed.is_complete);
        assert_eq!(parsed.total_entries_seen, 1);
    }

    #[test]
    fn concurrent_runs_do_not_clobber_logs() {
        // This test verifies that after migration, the legacy evidence
        // directory no longer exists, so concurrent FAC runs cannot
        // clobber logs via the legacy path.
        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");
        fs::write(evidence_dir.join("clippy.log"), b"old log").expect("write file");

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert_eq!(receipt.files_moved, 1);
        assert!(receipt.legacy_dir_removed);

        // After migration, the legacy evidence directory does not exist,
        // so no writes can reach it.
        assert!(
            !evidence_dir.exists(),
            "legacy evidence dir must not exist post-migration"
        );
    }

    #[test]
    fn complete_migration_reports_is_complete_true() {
        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");
        fs::write(evidence_dir.join("a.json"), b"{}").expect("write");

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert!(
            receipt.is_complete,
            "single-batch migration must be complete"
        );
        assert_eq!(receipt.total_entries_seen, 1);
    }

    #[test]
    fn receipt_roundtrip_with_new_fields() {
        // Verify the new `is_complete` and `total_entries_seen` fields
        // serialize and deserialize correctly, including serde defaults
        // for backwards compatibility.
        let receipt = LegacyEvidenceMigrationReceiptV1 {
            schema: MIGRATION_RECEIPT_SCHEMA.to_string(),
            files_moved: 5,
            files_failed: 0,
            legacy_dir_removed: true,
            skipped: false,
            skip_reason: None,
            is_complete: false,
            total_entries_seen: 10_001,
            migration_settled: false,
            file_results: Vec::new(),
        };

        let json = serde_json::to_string(&receipt).expect("serialize");
        let parsed: LegacyEvidenceMigrationReceiptV1 =
            serde_json::from_str(&json).expect("deserialize");
        assert!(!parsed.is_complete);
        assert_eq!(parsed.total_entries_seen, 10_001);

        // Backwards compatibility: a receipt WITHOUT `is_complete` should
        // default to `true` (pre-existing receipts were single-batch).
        let legacy_json = r#"{
            "schema": "apm2.fac.legacy_evidence_migration.v1",
            "files_moved": 3,
            "files_failed": 0,
            "legacy_dir_removed": true,
            "skipped": false,
            "file_results": []
        }"#;
        let legacy: LegacyEvidenceMigrationReceiptV1 =
            serde_json::from_str(legacy_json).expect("parse legacy");
        assert!(
            legacy.is_complete,
            "legacy receipt without is_complete must default to true"
        );
        assert_eq!(legacy.total_entries_seen, 0);
    }

    /// Regression: `read_dir` failure on an existing evidence directory must
    /// propagate as `LaneError`, not return a silent skip receipt.
    #[cfg(unix)]
    #[test]
    fn read_dir_permission_denied_is_lane_error() {
        use std::os::unix::fs::PermissionsExt;

        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");
        fs::write(evidence_dir.join("file.json"), b"{}").expect("write file");

        // Remove read permission on the evidence directory so `read_dir` fails.
        fs::set_permissions(&evidence_dir, fs::Permissions::from_mode(0o000))
            .expect("set permissions");

        let result = migrate_legacy_evidence(&fac_root);

        // Restore permissions before assertions so tempdir cleanup succeeds.
        fs::set_permissions(&evidence_dir, fs::Permissions::from_mode(0o755))
            .expect("restore permissions");

        assert!(
            result.is_err(),
            "read_dir failure must return Err, not a skip receipt"
        );
        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("cannot read legacy evidence directory"),
            "error should mention directory read failure, got: {err_msg}"
        );
    }

    /// Regression: non-regular file types (FIFOs) must be rejected, not
    /// treated as regular files.
    #[cfg(unix)]
    #[test]
    fn migration_rejects_fifo_entries() {
        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        // Create a regular file and a FIFO.
        fs::write(evidence_dir.join("real.json"), b"{}").expect("write real file");
        let fifo_path = evidence_dir.join("test.fifo");
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU).expect("create fifo");

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert_eq!(receipt.files_moved, 1, "regular file should be moved");
        assert_eq!(receipt.files_failed, 1, "FIFO should be counted as failed");

        // Verify the FIFO rejection is recorded with the correct error.
        let fifo_result = receipt
            .file_results
            .iter()
            .find(|r| r.filename == "test.fifo")
            .expect("should have result for FIFO");
        assert!(!fifo_result.success);
        assert!(
            fifo_result
                .error
                .as_deref()
                .unwrap()
                .contains("not a regular file"),
            "error message should indicate non-regular file rejection, got: {:?}",
            fifo_result.error
        );

        // FIFO should still be in evidence/ (not moved).
        assert!(
            evidence_dir.join("test.fifo").exists(),
            "FIFO should remain in evidence directory"
        );

        // Regular file should be in legacy/.
        let legacy_dir = fac_root.join("legacy");
        assert!(legacy_dir.join("real.json").exists());
    }

    /// Regression: unix sockets must be rejected the same as FIFOs.
    #[cfg(unix)]
    #[test]
    fn migration_rejects_unix_socket_entries() {
        use std::os::unix::net::UnixListener;

        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");

        // Create a regular file and a unix socket.
        fs::write(evidence_dir.join("real.json"), b"{}").expect("write real file");
        let sock_path = evidence_dir.join("test.sock");
        let _listener = UnixListener::bind(&sock_path).expect("bind socket");

        let receipt = migrate_legacy_evidence(&fac_root).expect("migrate");
        assert_eq!(receipt.files_moved, 1, "regular file should be moved");
        assert_eq!(
            receipt.files_failed, 1,
            "socket should be counted as failed"
        );

        let sock_result = receipt
            .file_results
            .iter()
            .find(|r| r.filename == "test.sock")
            .expect("should have result for socket");
        assert!(!sock_result.success);
        assert!(
            sock_result
                .error
                .as_deref()
                .unwrap()
                .contains("not a regular file"),
            "error message should indicate non-regular file rejection, got: {:?}",
            sock_result.error
        );
    }

    #[test]
    fn run_migration_to_completion_noop_when_no_evidence() {
        let (_root, fac_root) = setup_fac_root();
        let receipt = run_migration_to_completion(&fac_root).expect("migrate");
        assert!(receipt.skipped);
        assert!(receipt.is_complete);
    }

    #[test]
    fn run_migration_to_completion_single_batch() {
        let (_root, fac_root) = setup_fac_root();
        let evidence_dir = fac_root.join("evidence");
        fs::create_dir_all(&evidence_dir).expect("create evidence dir");
        for i in 0..5 {
            fs::write(evidence_dir.join(format!("file_{i}.json")), b"{}").expect("write");
        }

        let receipt = run_migration_to_completion(&fac_root).expect("migrate");
        assert!(receipt.is_complete);
        assert_eq!(receipt.files_moved, 5);
        assert!(!evidence_dir.exists(), "evidence dir should be removed");
    }
}
