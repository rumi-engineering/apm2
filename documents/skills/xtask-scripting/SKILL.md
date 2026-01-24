---
name: xtask-scripting
description: Standards for writing development scripts using the cargo-xtask pattern with xshell.
---

# APM2 xtask Scripting Standards

All development automation in APM2 MUST use the `xtask` pattern instead of shell scripts. This ensures our tooling is typesafe, testable, and cross-platform.

## Core Principles

### 1. Robustness
- **Error Handling:** Use `anyhow::Result<()>` for all task functions. Use `.context()` to provide meaningful error messages.
- **Strict Execution:** Always check command exit codes. `xshell::cmd!` does this by default unless `.ignore_status()` is called.
- **Atomic Operations:** When modifying files, prefer atomic operations or temporary files to avoid leaving the system in an inconsistent state.

### 2. Safety
- **Argument Escaping:** Always use `xshell` for command execution. Never manually concatenate strings to build shell commands.
- **Path Handling:** Use `std::path::PathBuf` and `Shell::create_dir` for directory operations.
- **Environment Isolation:** Use `Shell::push_env` or `Shell::push_dir` to manage state locally within a task.

### 3. Auditability
- **Command Logging:** Tasks should log their progress using the `tracing` crate.
- **Reporting:** Tasks that verify state or run tests should generate JSON evidence reports in the `evidence/` directory.
- **Dry Runs:** (Optional) Implement a `--dry-run` flag for destructive operations.

### 4. Performance
- **Minimal Rebuilds:** Avoid `cargo run` inside `xtask` if possible; prefer calling the binary directly or using `cargo build` only when necessary.
- **Concurrency:** Use `xshell`'s ability to run commands if appropriate, or standard Rust concurrency if the task is CPU-bound.

## Implementation Pattern

### Command Structure
Use `clap` subcommands in `xtask/src/main.rs`:

```rust
#[derive(Subcommand)]
enum Commands {
    /// Brief description of the task
    MyTask {
        /// Optional argument
        #[arg(long)]
        param: String,
    },
}
```

### Task Function Template
```rust
fn my_task(sh: &Shell, param: &str) -> Result<()> {
    tracing::info!("Executing my-task with param: {}", param);
    
    // Command execution
    cmd!(sh, "cargo build --package {param}").run()
        .context("Failed to build package")?;
        
    Ok(())
}
```

## Evidence Collection
Scripts that verify system properties (e.g., compatibility, integrity) MUST produce a JSON report following the schema used in existing evidence files. Use `serde` to define the report structure.
