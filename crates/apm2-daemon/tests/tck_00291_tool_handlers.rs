//! Integration tests for TCK-00291 real tool handlers.
//!
//! Verifies:
//! - `ReadFileHandler`: real FS reads, offsets, limits, root confinement
//! - `WriteFileHandler`: real FS writes, atomic writes, appends, parents
//! - `ExecuteHandler`: command execution, CWD, stdin, timeout, output capture
//! - **Sandbox security**: symlink-based escape attempts are rejected

#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use apm2_daemon::episode::handlers::{ExecuteHandler, ReadFileHandler, WriteFileHandler};
use apm2_daemon::episode::tool_handler::{
    ExecuteArgs, ReadArgs, ToolArgs, ToolHandler, ToolHandlerError, WriteArgs,
};
use tempfile::TempDir;

#[tokio::test]
async fn tool_handlers_real_io_read_write() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();

    // 1. Setup WriteFileHandler with temp root
    let write_handler = WriteFileHandler::with_root(root.clone());

    // 2. Write a file
    let args = ToolArgs::Write(WriteArgs {
        path: PathBuf::from("test.txt"),
        content: Some(b"Hello World".to_vec()),
        content_hash: None,
        create_parents: false,
        append: false,
    });
    let result = write_handler.execute(&args, None).await.unwrap();
    assert!(result.success);
    assert_eq!(result.budget_consumed.bytes_io, 11);

    // Verify file exists on disk
    let file_path = root.join("test.txt");
    assert!(file_path.exists());
    let content = tokio::fs::read(&file_path).await.unwrap();
    assert_eq!(content, b"Hello World");

    // 3. Setup ReadFileHandler with temp root
    let read_handler = ReadFileHandler::with_root(root.clone());

    // 4. Read the file
    let args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("test.txt"),
        offset: None,
        limit: None,
    });
    let result = read_handler.execute(&args, None).await.unwrap();
    assert!(result.success);
    assert_eq!(result.output, b"Hello World");
    assert_eq!(result.budget_consumed.bytes_io, 11);

    // 5. Test Offset/Limit
    let args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("test.txt"),
        offset: Some(6),
        limit: Some(5),
    });
    let result = read_handler.execute(&args, None).await.unwrap();
    assert!(result.success);
    assert_eq!(result.output, b"World");
}

#[tokio::test]
async fn tool_handlers_real_io_write_atomic_and_parents() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    let handler = WriteFileHandler::with_root(root.clone());

    // 1. Create parents
    let args = ToolArgs::Write(WriteArgs {
        path: PathBuf::from("nested/dir/file.txt"),
        content: Some(b"nested".to_vec()),
        content_hash: None,
        create_parents: true,
        append: false,
    });
    let result = handler.execute(&args, None).await.unwrap();
    assert!(result.success);

    let file_path = root.join("nested/dir/file.txt");
    assert!(file_path.exists());

    // 2. Append
    let args = ToolArgs::Write(WriteArgs {
        path: PathBuf::from("nested/dir/file.txt"),
        content: Some(b" content".to_vec()),
        content_hash: None,
        create_parents: false,
        append: true,
    });
    let result = handler.execute(&args, None).await.unwrap();
    assert!(result.success);

    let content = tokio::fs::read(&file_path).await.unwrap();
    assert_eq!(content, b"nested content");
}

#[tokio::test]
async fn tool_handlers_real_io_execute() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    // Use permissive mode for test that needs to execute arbitrary commands
    let handler = ExecuteHandler::with_root_permissive(root.clone());

    // 1. Simple echo
    let args = ToolArgs::Execute(ExecuteArgs {
        command: "echo".to_string(),
        args: vec!["hello".to_string()],
        cwd: None,
        stdin: None,
        timeout_ms: None,
    });
    let result = handler.execute(&args, None).await.unwrap();
    assert!(result.success);
    // output might contain newline
    let output_str = std::str::from_utf8(&result.output).unwrap();
    assert!(output_str.contains("hello"));

    // 2. CWD test
    // Create a file in a subdir
    tokio::fs::create_dir(root.join("subdir")).await.unwrap();
    tokio::fs::write(root.join("subdir/marker"), b"found me")
        .await
        .unwrap();

    // Execute ls in subdir
    let args = ToolArgs::Execute(ExecuteArgs {
        command: "ls".to_string(),
        args: vec![],
        cwd: Some(PathBuf::from("subdir")),
        stdin: None,
        timeout_ms: None,
    });
    let result = handler.execute(&args, None).await.unwrap();
    assert!(result.success);
    let output_str = std::str::from_utf8(&result.output).unwrap();
    assert!(output_str.contains("marker"));

    // 3. Stdin test (cat)
    let args = ToolArgs::Execute(ExecuteArgs {
        command: "cat".to_string(),
        args: vec![],
        cwd: None,
        stdin: Some(b"from stdin".to_vec()),
        timeout_ms: None,
    });
    let result = handler.execute(&args, None).await.unwrap();
    assert!(result.success);
    assert_eq!(result.output, b"from stdin");
}

#[tokio::test]
async fn tool_handlers_real_io_execute_timeout() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    // Use permissive mode for test that needs to execute sleep command
    let handler = ExecuteHandler::with_root_permissive(root.clone());

    let args = ToolArgs::Execute(ExecuteArgs {
        command: "sleep".to_string(),
        args: vec!["1".to_string()], // Sleep 1s
        cwd: None,
        stdin: None,
        timeout_ms: Some(100), // Timeout 100ms
    });

    let result = handler.execute(&args, None).await;
    assert!(matches!(
        result,
        Err(apm2_daemon::episode::tool_handler::ToolHandlerError::ExecutionFailed { .. })
    ));
    // Verify error message mentions timeout
    if let Err(apm2_daemon::episode::tool_handler::ToolHandlerError::ExecutionFailed {
        message,
        ..
    }) = result
    {
        assert!(message.contains("timed out"));
    }
}

// =============================================================================
// Sandbox escape tests (symlink-based)
// =============================================================================

/// Tests that `ExecuteHandler` rejects cwd paths that resolve outside the
/// workspace root via symlinks.
///
/// This is a critical security test - an attacker could create a symlink
/// inside the workspace that points outside (e.g., to /tmp or /), then
/// supply that symlink path as cwd. Without proper canonicalization, the
/// command would execute in the external directory, escaping the sandbox.
#[cfg(unix)]
#[tokio::test]
async fn tool_handlers_execute_rejects_cwd_symlink_escape() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();

    // Create a symlink inside the workspace that points outside
    let escape_link = root.join("escape");
    symlink("/tmp", &escape_link).expect("failed to create symlink");

    // Use permissive mode for this test since we're testing symlink rejection, not
    // allowlist
    let handler = ExecuteHandler::with_root_permissive(root.clone());

    // Attempt to execute with cwd set to the symlink
    let args = ToolArgs::Execute(ExecuteArgs {
        command: "pwd".to_string(),
        args: vec![],
        cwd: Some(PathBuf::from("escape")),
        stdin: None,
        timeout_ms: None,
    });

    let result = handler.execute(&args, None).await;

    // Must fail with PathValidation error
    assert!(
        matches!(result, Err(ToolHandlerError::PathValidation { .. })),
        "Expected PathValidation error for symlink escape, got: {result:?}"
    );

    // Verify the error mentions symlink or escape
    if let Err(ToolHandlerError::PathValidation { reason, .. }) = result {
        assert!(
            reason.contains("symlink") || reason.contains("escapes"),
            "Error should mention symlink sandbox escape: {reason}"
        );
    }
}

/// Tests that `ReadFileHandler` rejects symlinks that resolve outside the
/// workspace root.
#[cfg(unix)]
#[tokio::test]
async fn tool_handlers_read_rejects_symlink_escape() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();

    // Create /tmp/test_escape_file for the symlink to point to
    let external_file = std::path::Path::new("/tmp/test_escape_file_read");
    std::fs::write(external_file, b"secret").ok();

    // Create a symlink inside the workspace pointing outside
    let escape_link = root.join("escape_file");
    symlink(external_file, &escape_link).expect("failed to create symlink");

    let handler = ReadFileHandler::with_root(root.clone());

    let args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("escape_file"),
        offset: None,
        limit: None,
    });

    let result = handler.execute(&args, None).await;

    assert!(
        matches!(result, Err(ToolHandlerError::PathValidation { .. })),
        "Expected PathValidation error for symlink escape, got: {result:?}"
    );

    // Cleanup
    let _ = std::fs::remove_file(external_file);
}

/// Tests that `WriteFileHandler` rejects symlinks that resolve outside the
/// workspace root.
#[cfg(unix)]
#[tokio::test]
async fn tool_handlers_write_rejects_symlink_escape() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();

    // Target file outside workspace
    let external_file = std::path::Path::new("/tmp/test_escape_file_write");
    std::fs::write(external_file, b"original").ok();

    // Create a symlink inside the workspace pointing outside
    let escape_link = root.join("escape_file");
    symlink(external_file, &escape_link).expect("failed to create symlink");

    let handler = WriteFileHandler::with_root(root.clone());

    let args = ToolArgs::Write(WriteArgs {
        path: PathBuf::from("escape_file"),
        content: Some(b"malicious overwrite".to_vec()),
        content_hash: None,
        create_parents: false,
        append: false,
    });

    let result = handler.execute(&args, None).await;

    assert!(
        matches!(result, Err(ToolHandlerError::PathValidation { .. })),
        "Expected PathValidation error for symlink escape, got: {result:?}"
    );

    // Verify the external file was NOT modified
    let content = std::fs::read(external_file).unwrap_or_default();
    assert_eq!(
        content, b"original",
        "External file should not have been modified"
    );

    // Cleanup
    let _ = std::fs::remove_file(external_file);
}

/// Tests that `ExecuteHandler` handles non-existent cwd gracefully.
#[tokio::test]
async fn tool_handlers_execute_nonexistent_cwd() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    // Use permissive mode for this test since we're testing cwd handling, not
    // allowlist
    let handler = ExecuteHandler::with_root_permissive(root.clone());

    let args = ToolArgs::Execute(ExecuteArgs {
        command: "ls".to_string(),
        args: vec![],
        cwd: Some(PathBuf::from("nonexistent_directory")),
        stdin: None,
        timeout_ms: None,
    });

    let result = handler.execute(&args, None).await;

    // Should fail because the directory doesn't exist
    assert!(
        matches!(result, Err(ToolHandlerError::ExecutionFailed { .. })),
        "Expected ExecutionFailed for non-existent cwd, got: {result:?}"
    );
}
