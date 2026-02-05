//! TCK-00318 Security Integration Tests
//!
//! Tests for workspace security including argument injection prevention
//! and path traversal prevention.

use apm2_core::fac::{ChangeKind, ChangeSetBundleV1, FileChange, GitObjectRef, HashAlgo};
use apm2_daemon::episode::workspace::{WorkspaceError, WorkspaceManager};

#[test]
fn test_checkout_rejects_argument_injection() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let manager = WorkspaceManager::new(temp_dir.path().to_path_buf());

    // Leading hyphen
    let result = manager.checkout("-rf");
    assert!(matches!(result, Err(WorkspaceError::InvalidCommitRef(_))));

    // Invalid characters (semicolon)
    let result = manager.checkout("HEAD; rm -rf /");
    assert!(matches!(result, Err(WorkspaceError::InvalidCommitRef(_))));

    // Valid ref
    // We expect BaseCommitNotFound or GitOperationFailed because repo doesn't
    // exist, but NOT InvalidCommitRef.
    let result = manager.checkout("main");
    assert!(matches!(
        result,
        Err(WorkspaceError::GitOperationFailed(_) | WorkspaceError::BaseCommitNotFound(_))
    ));
}

#[test]
fn test_apply_rejects_diff_manifest_mismatch() {
    // Setup workspace
    let temp_dir = tempfile::TempDir::new().unwrap();
    let workspace_root = temp_dir.path().to_path_buf();

    // Initialize a git repo so git apply checks work
    std::process::Command::new("git")
        .arg("init")
        .current_dir(&workspace_root)
        .output()
        .expect("git init failed");

    // Create an initial commit with files
    std::fs::write(workspace_root.join("allowed.txt"), "initial\n").unwrap();
    std::fs::write(workspace_root.join("secret.txt"), "secret\n").unwrap();

    std::process::Command::new("git")
        .args(["add", "."])
        .current_dir(&workspace_root)
        .output()
        .expect("git add failed");

    std::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(&workspace_root)
        .output()
        .expect("git commit failed");

    let manager = WorkspaceManager::new(workspace_root);

    // Create a diff that modifies BOTH allowed.txt and secret.txt
    // But manifest ONLY lists allowed.txt
    let diff_content = "diff --git a/allowed.txt b/allowed.txt\nindex e69de29..d227096 100644\n--- a/allowed.txt\n+++ b/allowed.txt\n@@ -1 +1 @@\n-initial\n+modified\ndiff --git a/secret.txt b/secret.txt\nindex e69de29..d227096 100644\n--- a/secret.txt\n+++ b/secret.txt\n@@ -1 +1 @@\n-secret\n+leaked\n";
    let diff_bytes = diff_content.as_bytes();
    let diff_hash = *blake3::hash(diff_bytes).as_bytes();

    let bundle = ChangeSetBundleV1::builder()
        .changeset_id("cs-mismatch")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "0000000000000000000000000000000000000000".to_string(),
        })
        .diff_hash(diff_hash)
        .file_manifest(vec![FileChange {
            path: "allowed.txt".to_string(),
            change_kind: ChangeKind::Modify,
            old_path: None,
        }])
        .binary_detected(false)
        .build()
        .expect("valid bundle");

    // Apply should fail
    let result =
        manager.apply_with_diff_and_timestamp(&bundle, diff_bytes, 1_234_567_890_123_456_789_u64);

    // Assert specific error
    match result {
        Err(WorkspaceError::DiffManifestMismatch { diff_path }) => {
            assert!(diff_path.contains("secret.txt"));
        },
        Err(e) => panic!("Expected DiffManifestMismatch, got: {e:?}"),
        Ok(_) => panic!("Expected error, got success"),
    }
}

#[test]
fn test_apply_allows_valid_diff_manifest_match() {
    // Setup workspace
    let temp_dir = tempfile::TempDir::new().unwrap();
    let workspace_root = temp_dir.path().to_path_buf();

    std::process::Command::new("git")
        .arg("init")
        .current_dir(&workspace_root)
        .output()
        .expect("git init failed");

    std::fs::write(workspace_root.join("allowed.txt"), "initial\n").unwrap();

    std::process::Command::new("git")
        .args(["add", "."])
        .current_dir(&workspace_root)
        .output()
        .expect("git add failed");

    std::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(&workspace_root)
        .output()
        .expect("git commit failed");

    let manager = WorkspaceManager::new(workspace_root);

    // Create a diff that modifies allowed.txt
    let diff_content = "diff --git a/allowed.txt b/allowed.txt\nindex e69de29..d227096 100644\n--- a/allowed.txt\n+++ b/allowed.txt\n@@ -1 +1 @@\n-initial\n+modified\n";
    let diff_bytes = diff_content.as_bytes();
    let diff_hash = *blake3::hash(diff_bytes).as_bytes();

    let bundle = ChangeSetBundleV1::builder()
        .changeset_id("cs-match")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "0000000000000000000000000000000000000000".to_string(),
        })
        .diff_hash(diff_hash)
        .file_manifest(vec![FileChange {
            path: "allowed.txt".to_string(),
            change_kind: ChangeKind::Modify,
            old_path: None,
        }])
        .binary_detected(false)
        .build()
        .expect("valid bundle");

    // Apply should succeed
    let result =
        manager.apply_with_diff_and_timestamp(&bundle, diff_bytes, 1_234_567_890_123_456_789_u64);
    assert!(result.is_ok());
}
