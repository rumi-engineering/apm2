//! `apm2 fac logs` — discover local pipeline/evidence/review logs and
//! selector-based zoom-in.

use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::evidence::LANE_EVIDENCE_GATES;
use super::findings::{
    SelectorToken, parse_selector, parse_selector_type, render_tool_output_selector,
};
use super::findings_store;
use super::types::apm2_home_dir;
use crate::exit_codes::codes as exit_codes;

const SELECTOR_ZOOM_SCHEMA: &str = "apm2.fac.selector_zoom.v1";

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

#[derive(Debug, Clone, Serialize)]
struct SelectorZoomSummary {
    schema: String,
    selector_type: String,
    selector: String,
    content_digest: String,
    content_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha_binding: Option<String>,
    payload: serde_json::Value,
}

// ── Selector zoom-in ────────────────────────────────────────────────────────

fn run_selector_zoom(repo: &str, selector_type: &str, selector: &str, json_output: bool) -> u8 {
    match resolve_selector_zoom(repo, selector_type, selector) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Selector Zoom");
                println!("  Type:         {}", summary.selector_type);
                println!("  Selector:     {}", summary.selector);
                println!("  Digest:       {}", summary.content_digest);
                println!("  Content Ref:  {}", summary.content_ref);
                if let Some(sha) = &summary.sha_binding {
                    println!("  SHA Binding:  {sha}");
                }
                println!(
                    "  Payload:      {}",
                    serde_json::to_string_pretty(&summary.payload)
                        .unwrap_or_else(|_| "{}".to_string())
                );
            }
            exit_codes::SUCCESS
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_selector_zoom_failed",
                    "message": err,
                    "selector_type": selector_type,
                    "selector": selector,
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

fn resolve_selector_zoom(
    repo: &str,
    selector_type: &str,
    selector: &str,
) -> Result<SelectorZoomSummary, String> {
    let parsed_type = parse_selector_type(selector_type)?;
    let parsed_selector = parse_selector(parsed_type, selector)?;

    match parsed_selector {
        SelectorToken::Finding(finding) => {
            let bundle = findings_store::load_findings_bundle(
                &finding.owner_repo,
                finding.pr,
                &finding.sha,
            )?
            .ok_or_else(|| {
                format!(
                    "missing SHA-bound findings bundle for repo={} pr={} sha={}",
                    finding.owner_repo, finding.pr, finding.sha
                )
            })?;

            let dimension = findings_store::find_dimension(&bundle, &finding.dimension)
                .ok_or_else(|| {
                    format!(
                        "missing SHA-bound findings for dimension `{}` in repo={} pr={} sha={}",
                        finding.dimension, finding.owner_repo, finding.pr, finding.sha
                    )
                })?;

            let finding_record =
                findings_store::find_finding(&bundle, &finding.dimension, &finding.finding_id)
                    .ok_or_else(|| {
                        format!(
                            "missing SHA-bound finding `{}` for dimension `{}`",
                            finding.finding_id, finding.dimension
                        )
                    })?;

            let bundle_path = findings_store::findings_bundle_path(
                &finding.owner_repo,
                finding.pr,
                &finding.sha,
            )?;
            let content_ref = format!("{}#{}", bundle_path.display(), finding_record.finding_id);

            let content_digest = if finding_record.evidence_digest.trim().is_empty() {
                sha256_hex(finding_record.summary.as_bytes())
            } else {
                finding_record.evidence_digest.clone()
            };

            let payload = serde_json::json!({
                "owner_repo": finding.owner_repo,
                "pr": finding.pr,
                "dimension": finding.dimension,
                "status": dimension.status,
                "verdict": dimension.verdict,
                "finding_id": finding_record.finding_id,
                "severity": finding_record.severity,
                "summary": finding_record.summary,
            });

            Ok(SelectorZoomSummary {
                schema: SELECTOR_ZOOM_SCHEMA.to_string(),
                selector_type: parsed_type.as_str().to_string(),
                selector: selector.to_string(),
                content_digest,
                content_ref,
                sha_binding: Some(finding.sha),
                payload,
            })
        },
        SelectorToken::ToolOutput(tool_output) => {
            // Fail closed: verify gate cache proves this gate ran for the requested SHA.
            let gate_cache =
                super::gate_cache::GateCache::load(&tool_output.sha).ok_or_else(|| {
                    format!(
                        "no gate cache found for SHA {} — cannot validate tool output selector",
                        tool_output.sha
                    )
                })?;
            let cached_result = gate_cache.get(&tool_output.gate).ok_or_else(|| {
                format!(
                    "gate `{}` not found in cache for SHA {} — cannot validate tool output selector",
                    tool_output.gate, tool_output.sha
                )
            })?;

            // Resolve log path from the SHA-bound gate cache entry rather than
            // searching by mtime, which could return a log from a different SHA.
            let evidence_path = cached_result
                .log_path
                .as_ref()
                .map(PathBuf::from)
                .filter(|p| p.exists())
                .ok_or_else(|| {
                    format!(
                        "no SHA-bound evidence log path found for gate `{}` at SHA {} — \
                         cached log_path is missing or the file no longer exists",
                        tool_output.gate, tool_output.sha
                    )
                })?;
            // Open with O_NOFOLLOW to atomically reject symlinks at the
            // kernel level, preventing symlink traversal attacks on
            // evidence log paths.
            let content = {
                let mut options = fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                options.custom_flags(libc::O_NOFOLLOW);
                let mut file = options.open(&evidence_path).map_err(|err| {
                    format!(
                        "failed to open tool output log {}: {err}",
                        evidence_path.display()
                    )
                })?;
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).map_err(|err| {
                    format!(
                        "failed to read tool output log {}: {err}",
                        evidence_path.display()
                    )
                })?;
                buf
            };
            let digest = sha256_hex(&content);
            let content_ref = evidence_path.display().to_string();
            let text = String::from_utf8_lossy(&content);
            let payload = serde_json::json!({
                "owner_repo": repo,
                "gate": tool_output.gate,
                "bytes": content.len(),
                "excerpt": truncate_excerpt(&text, 40, 4096),
            });

            Ok(SelectorZoomSummary {
                schema: SELECTOR_ZOOM_SCHEMA.to_string(),
                selector_type: parsed_type.as_str().to_string(),
                selector: render_tool_output_selector(&tool_output.sha, &tool_output.gate),
                content_digest: digest,
                content_ref,
                sha_binding: Some(tool_output.sha),
                payload,
            })
        },
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn truncate_excerpt(text: &str, max_lines: usize, max_chars: usize) -> String {
    let mut out = String::new();
    for (idx, line) in text.lines().enumerate() {
        if idx >= max_lines || out.len() >= max_chars {
            break;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(line);
    }
    if out.len() > max_chars {
        out.truncate(max_chars);
    }
    out
}

fn lane_evidence_log_dirs(home: &Path) -> Vec<PathBuf> {
    let lanes_dir = home.join("private/fac/lanes");
    let mut logs = Vec::new();
    let Ok(lanes) = fs::read_dir(&lanes_dir) else {
        return logs;
    };

    for lane_dir_entry in lanes.filter_map(Result::ok) {
        let lane_dir_path = lane_dir_entry.path();
        let lane_is_dir = lane_dir_path
            .metadata()
            .map(|meta| meta.is_dir())
            .unwrap_or(false);
        if !lane_is_dir {
            continue;
        }

        let jobs_dir = lane_dir_path.join("logs");
        let mut latest_job: Option<(PathBuf, SystemTime)> = None;
        let Ok(jobs) = fs::read_dir(&jobs_dir) else {
            continue;
        };

        for job_dir_entry in jobs.filter_map(Result::ok) {
            let job_dir_path = job_dir_entry.path();
            let is_dir = job_dir_entry.file_type().map_or_else(
                |_| {
                    job_dir_path
                        .metadata()
                        .map(|meta| meta.is_dir())
                        .unwrap_or(false)
                },
                |ft| ft.is_dir(),
            );
            if !is_dir {
                continue;
            }

            let modified = job_dir_path
                .metadata()
                .and_then(|meta| meta.modified())
                .unwrap_or(UNIX_EPOCH);
            match &latest_job {
                Some((_, current)) if *current >= modified => {},
                _ => latest_job = Some((job_dir_path, modified)),
            }
        }

        if let Some((latest_job_dir, _)) = latest_job {
            for gate in LANE_EVIDENCE_GATES {
                logs.push(latest_job_dir.join(format!("{gate}.log")));
            }
        }
    }

    logs.sort();
    logs
}

#[allow(dead_code)] // Retained for future log discovery / fallback use cases.
fn find_latest_evidence_gate_log(home: &Path, gate: &str) -> Option<PathBuf> {
    let expected_name = format!("{gate}.log");
    let mut latest: Option<(PathBuf, SystemTime)> = None;
    for path in lane_evidence_log_dirs(home) {
        if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            continue;
        }
        if !path.exists() {
            continue;
        }
        let modified = path
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(UNIX_EPOCH);
        if latest
            .as_ref()
            .is_none_or(|(_, current)| modified > *current)
        {
            latest = Some((path, modified));
        }
    }
    latest.map(|(path, _)| path)
}

// ── Log discovery ───────────────────────────────────────────────────────────

fn discover_logs(pr_number: Option<u32>) -> Result<LogsSummary, String> {
    let home = apm2_home_dir()?;
    let mut entries = Vec::new();

    // Evidence gate logs (always relevant).
    for path in lane_evidence_log_dirs(&home) {
        push_entry(&mut entries, "evidence", &path);
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

pub fn run_logs(
    pr_number: Option<u32>,
    repo: &str,
    selector_type: Option<&str>,
    selector: Option<&str>,
    json_output: bool,
) -> u8 {
    match (selector_type, selector) {
        (Some(selector_type), Some(selector)) => {
            return run_selector_zoom(repo, selector_type, selector, json_output);
        },
        (Some(_), None) | (None, Some(_)) => {
            let message = "selector zoom requires both --selector-type and --selector".to_string();
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_logs_selector_args_invalid",
                    "message": message,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {message}");
            }
            return exit_codes::GENERIC_ERROR;
        },
        (None, None) => {},
    }

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

#[cfg(test)]
mod tests {
    use super::{sha256_hex, truncate_excerpt};

    #[test]
    fn test_truncate_excerpt_respects_bounds() {
        let text = "l1\nl2\nl3\nl4\nl5";
        let excerpt = truncate_excerpt(text, 3, 100);
        assert_eq!(excerpt, "l1\nl2\nl3");
    }

    #[test]
    fn test_sha256_hex_stable() {
        let digest = sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
