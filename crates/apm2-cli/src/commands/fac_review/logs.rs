//! `apm2 fac logs` — discover and display local pipeline/evidence/review logs.

use std::fs;
use std::path::PathBuf;

use serde::Serialize;

use super::types::apm2_home_dir;
use crate::exit_codes::codes as exit_codes;

// ── Summary types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct LogEntry {
    category: String,
    path: String,
    size_bytes: u64,
    exists: bool,
}

#[derive(Debug, Clone, Serialize)]
struct LogsSummary {
    pr_number: Option<u32>,
    entries: Vec<LogEntry>,
}

// ── Log discovery ───────────────────────────────────────────────────────────

fn discover_logs(pr_number: Option<u32>) -> Result<LogsSummary, String> {
    let home = apm2_home_dir()?;
    let mut entries = Vec::new();

    // Evidence gate logs (always relevant).
    let evidence_dir = home.join("private/fac/evidence");
    if evidence_dir.is_dir() {
        let gate_names = [
            "rustfmt",
            "clippy",
            "doc",
            "test",
            "test_safety_guard",
            "workspace_integrity",
            "review_artifact_lint",
        ];
        for gate in &gate_names {
            let path = evidence_dir.join(format!("{gate}.log"));
            push_entry(&mut entries, "evidence", &path);
        }
    }

    // Pipeline logs (filter by PR if provided).
    let pipeline_dir = home.join("pipeline_logs");
    if pipeline_dir.is_dir() {
        push_matching_dir_entries(&mut entries, "pipeline", &pipeline_dir, pr_number)?;
    }

    // Review dispatch logs (filter by PR if provided).
    let dispatch_dir = home.join("review_dispatch");
    if dispatch_dir.is_dir() {
        push_matching_dir_entries(&mut entries, "review_dispatch", &dispatch_dir, pr_number)?;
    }

    // Review events stream.
    let events_path = home.join("review_events.ndjson");
    push_entry(&mut entries, "events", &events_path);

    Ok(LogsSummary { pr_number, entries })
}

fn push_entry(entries: &mut Vec<LogEntry>, category: &str, path: &PathBuf) {
    let exists = path.exists();
    let size_bytes = if exists {
        fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    entries.push(LogEntry {
        category: category.to_string(),
        path: path.display().to_string(),
        size_bytes,
        exists,
    });
}

fn push_matching_dir_entries(
    entries: &mut Vec<LogEntry>,
    category: &str,
    dir: &PathBuf,
    pr_number: Option<u32>,
) -> Result<(), String> {
    let read_dir =
        fs::read_dir(dir).map_err(|e| format!("failed to read {}: {e}", dir.display()))?;
    let pr_prefix = pr_number.map(|n| format!("pr{n}"));

    let mut paths: Vec<PathBuf> = read_dir
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && pr_prefix.as_ref().is_none_or(|prefix| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(prefix.as_str()))
                })
        })
        .collect();
    paths.sort();

    for path in paths {
        push_entry(entries, category, &path);
    }
    Ok(())
}

// ── Public entry point ──────────────────────────────────────────────────────

pub fn run_logs(pr_number: Option<u32>, json_output: bool) -> u8 {
    match discover_logs(pr_number) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Logs");
                if let Some(n) = summary.pr_number {
                    println!("  Filter: PR #{n}");
                }

                let existing: Vec<_> = summary.entries.iter().filter(|e| e.exists).collect();
                let missing: Vec<_> = summary.entries.iter().filter(|e| !e.exists).collect();

                if existing.is_empty() {
                    println!("  No log files found.");
                } else {
                    for entry in &existing {
                        let size_kb = entry.size_bytes / 1024;
                        println!("  [{:>16}] {} ({size_kb} KB)", entry.category, entry.path);
                    }
                }

                if !missing.is_empty() {
                    println!("  Missing:");
                    for entry in &missing {
                        println!("    [{:>16}] {}", entry.category, entry.path);
                    }
                }

                if !existing.is_empty() {
                    println!();
                    // Show the most useful log first — latest pipeline or latest evidence failure.
                    if let Some(latest) = existing.iter().rev().find(|e| {
                        e.category == "pipeline" || e.category == "evidence" && e.size_bytes > 0
                    }) {
                        println!("  Hint: tail -f {}", latest.path);
                    }
                }
            }
            exit_codes::SUCCESS
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_logs_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}
