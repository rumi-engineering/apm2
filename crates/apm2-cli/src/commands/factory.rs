use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use apm2_core::adapter::{AdapterEventPayload, ClaudeCodeAdapter, ClaudeCodeConfig};
use tokio::signal;
use uuid::Uuid;

/// Maximum allowed size for specification files (1 MiB).
/// This prevents memory exhaustion and large argument issues.
const MAX_SPEC_SIZE: u64 = 1024 * 1024;

pub async fn run(spec_file: &Path, format: &str) -> Result<()> {
    if !spec_file.exists() {
        bail!("Spec file not found: {}", spec_file.display());
    }

    // Security: Enforce file size limit to prevent DoS/memory exhaustion
    let metadata = std::fs::metadata(spec_file).context("Failed to get spec file metadata")?;
    if metadata.len() > MAX_SPEC_SIZE {
        bail!(
            "Spec file too large: {} bytes (max {} bytes)",
            metadata.len(),
            MAX_SPEC_SIZE
        );
    }

    // Read spec file content with bounded reader
    let mut spec_content = String::new();
    File::open(spec_file)
        .context("Failed to open spec file")?
        .take(MAX_SPEC_SIZE)
        .read_to_string(&mut spec_content)
        .context("Failed to read spec file")?;

    // Construct prompt
    let prompt = format!("Please implement the following specification:\n\n{spec_content}");

    // Security: Write prompt to a temporary file to avoid hitting OS ARG_MAX limits
    // and to prevent exposure of sensitive content in process listings (though args
    // are redacted, length can still be an issue).
    let mut prompt_file = tempfile::NamedTempFile::new().context("Failed to create temp file")?;
    prompt_file
        .write_all(prompt.as_bytes())
        .context("Failed to write prompt to temp file")?;

    // Ensure content is written to disk
    prompt_file.flush().context("Failed to flush temp file")?;

    let prompt_path = prompt_file.path().to_string_lossy().to_string();

    if format == "text" {
        println!(
            "Starting factory session with spec: {}",
            spec_file.display()
        );
    }

    // Security: Use high-entropy session ID
    let session_id = format!("factory-{}", Uuid::new_v4());

    // Configure adapter
    // Pass the prompt file path as an argument. The Claude Code CLI (and underlying
    // model) should interpret a single file argument as the prompt/context.
    let config = ClaudeCodeConfig::new(&session_id)
        .with_args(vec![prompt_path])
        .with_stall_timeout(Duration::from_secs(300));

    let mut adapter = ClaudeCodeAdapter::new(config);

    // Start adapter
    adapter.start().await.context("Failed to start adapter")?;

    if format == "text" {
        println!("Session started (PID: {:?})", adapter.pid());
    }

    // Event loop
    let mut exit_code = 0;

    // Handle Ctrl+C
    // We need to pin sigint to await it in select!
    let sigint = signal::ctrl_c();
    tokio::pin!(sigint);

    // Keep prompt_file alive for the duration of the process start
    // (Actually, checking if we can drop it? The process reads it on start.
    // But to be safe, we keep it until the end or until we know it's read.)
    // Since 'claude' might read it at any point during startup, keeping it in scope
    // is safe.

    loop {
        tokio::select! {
            _ = &mut sigint => {
                if format == "text" {
                    println!("\nReceived Ctrl+C, stopping...");
                }
                adapter.stop().await?;
                break;
            }
            // Poll the adapter for events
            result = adapter.poll() => {
                match result {
                    Ok(Some(event)) => {
                        handle_event(&event, format);

                        if let AdapterEventPayload::ProcessExited(exit) = event.payload {
                            if format == "text" {
                                println!("Process exited with code {:?}", exit.exit_code);
                            }
                            exit_code = exit.exit_code.unwrap_or(1);
                            break;
                        }
                    }
                    Ok(None) => {
                        // No events currently available, sleep briefly to avoid busy loop
                        // since poll() is non-blocking for the internal channel check
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        eprintln!("Adapter error: {e}");
                        adapter.stop().await?;
                        exit_code = 1;
                        break;
                    }
                }
            }
        }
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

fn handle_event(event: &apm2_core::adapter::AdapterEvent, format: &str) {
    if format == "json" {
        if let Ok(json) = serde_json::to_string(event) {
            println!("{json}");
        }
        return;
    }

    // Text format handling
    match &event.payload {
        AdapterEventPayload::ProcessStarted(started) => {
            println!("Agent process started: {}", started.command);
        },
        AdapterEventPayload::Progress(progress) => {
            println!("> {}", progress.description);
        },
        AdapterEventPayload::ToolRequestDetected(req) => {
            println!("Tool Request: {}", req.tool_name);
        },
        AdapterEventPayload::StallDetected(stall) => {
            println!("WARNING: Stall detected ({:?} idle)", stall.idle_duration);
        },
        AdapterEventPayload::Diagnostic(diag) => {
            eprintln!("[{:?}] {}", diag.severity, diag.message);
        },
        _ => {},
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn test_max_spec_size_constant() {
        assert_eq!(MAX_SPEC_SIZE, 1024 * 1024);
    }

    #[tokio::test]
    async fn test_run_missing_file() {
        let path = Path::new("nonexistent_file.md");
        let result = run(path, "text").await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Spec file not found")
        );
    }

    #[tokio::test]
    async fn test_run_file_too_large() {
        // Create a temporary file larger than MAX_SPEC_SIZE
        let mut file = tempfile::NamedTempFile::new().unwrap();
        // Use expect() since this conversion should always succeed on 64-bit systems
        // and failing here in tests is acceptable
        #[allow(clippy::cast_possible_truncation)]
        let size = (MAX_SPEC_SIZE + 100) as usize;
        let big_data = vec![0u8; size];
        file.write_all(&big_data).unwrap();
        file.flush().unwrap();

        let result = run(file.path(), "text").await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Spec file too large")
        );
    }
}
