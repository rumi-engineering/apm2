//! `apm2 fac logs` — discover local pipeline/evidence/review logs and
//! selector-based zoom-in.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::barrier::{ensure_gh_cli_ready, resolve_authenticated_gh_login};
use super::selector::{
    SelectorToken, parse_selector, parse_selector_type, render_tool_output_selector,
};
use super::types::{QUALITY_MARKER, SECURITY_MARKER, apm2_home_dir, validate_expected_head_sha};
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

#[derive(Debug, Clone, Deserialize)]
struct IssueComment {
    id: u64,
    body: String,
    html_url: String,
    #[serde(default)]
    user: Option<IssueUser>,
}

#[derive(Debug, Clone, Deserialize)]
struct IssueUser {
    login: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReviewMetadata {
    schema: String,
    review_type: String,
    pr_number: u32,
    head_sha: String,
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
            ensure_gh_cli_ready()?;
            let expected_author = resolve_authenticated_gh_login().ok_or_else(|| {
                "failed to resolve authenticated GitHub login for trusted selector zoom".to_string()
            })?;

            let comment = fetch_issue_comment(&finding.owner_repo, finding.comment_id)?;
            let comment_author = comment
                .user
                .as_ref()
                .map(|user| user.login.as_str())
                .unwrap_or_default();
            if !comment_author.eq_ignore_ascii_case(&expected_author) {
                return Err(format!(
                    "comment {} was authored by `{comment_author}`, expected trusted login `{expected_author}`",
                    comment.id
                ));
            }

            let marker = marker_for_dimension(&finding.dimension)?;
            let metadata = parse_metadata_from_comment(&comment.body, marker)?;
            if metadata.schema != "apm2.review.metadata.v1" {
                return Err(format!(
                    "invalid metadata schema `{}` for finding selector",
                    metadata.schema
                ));
            }
            validate_expected_head_sha(&metadata.head_sha)?;
            if metadata.pr_number != finding.pr {
                return Err(format!(
                    "selector PR #{} does not match comment metadata PR #{}",
                    finding.pr, metadata.pr_number
                ));
            }
            if !metadata.head_sha.eq_ignore_ascii_case(&finding.sha) {
                return Err(format!(
                    "selector SHA {} does not match comment metadata SHA {}",
                    finding.sha, metadata.head_sha
                ));
            }
            if normalize_review_type(&metadata.review_type) != finding.dimension {
                return Err(format!(
                    "selector dimension `{}` does not match comment metadata dimension `{}`",
                    finding.dimension, metadata.review_type
                ));
            }

            let line_text = comment
                .body
                .lines()
                .nth(finding.line.saturating_sub(1))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    format!(
                        "selector line {} is missing or empty in comment {}",
                        finding.line, finding.comment_id
                    )
                })?;

            let digest = sha256_hex(comment.body.as_bytes());
            let content_ref = format!("{}#line-{}", comment.html_url, finding.line);
            let payload = serde_json::json!({
                "owner_repo": finding.owner_repo,
                "pr": finding.pr,
                "dimension": finding.dimension,
                "comment_id": finding.comment_id,
                "line": finding.line,
                "text": line_text,
            });

            Ok(SelectorZoomSummary {
                schema: SELECTOR_ZOOM_SCHEMA.to_string(),
                selector_type: parsed_type.as_str().to_string(),
                selector: selector.to_string(),
                content_digest: digest,
                content_ref,
                sha_binding: Some(finding.sha),
                payload,
            })
        },
        SelectorToken::ToolOutput(tool_output) => {
            let evidence_path = apm2_home_dir()?
                .join("private")
                .join("fac")
                .join("evidence")
                .join(format!("{}.log", tool_output.gate));
            let content = fs::read(&evidence_path).map_err(|err| {
                format!(
                    "failed to read tool output log {}: {err}",
                    evidence_path.display()
                )
            })?;
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

fn fetch_issue_comment(owner_repo: &str, comment_id: u64) -> Result<IssueComment, String> {
    let endpoint = format!("/repos/{owner_repo}/issues/comments/{comment_id}");
    let output = Command::new("gh")
        .args(["api", &endpoint])
        .output()
        .map_err(|err| format!("failed to execute gh api for comment lookup: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed fetching comment {}: {}",
            comment_id,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    serde_json::from_slice::<IssueComment>(&output.stdout)
        .map_err(|err| format!("failed to parse comment payload for {comment_id}: {err}"))
}

fn marker_for_dimension(dimension: &str) -> Result<&'static str, String> {
    match dimension {
        "security" => Ok(SECURITY_MARKER),
        "code-quality" => Ok(QUALITY_MARKER),
        other => Err(format!(
            "unsupported finding dimension `{other}` for selector zoom"
        )),
    }
}

fn normalize_review_type(input: &str) -> String {
    match input.trim().to_ascii_lowercase().as_str() {
        "security" => "security".to_string(),
        "quality" | "code-quality" | "code_quality" => "code-quality".to_string(),
        other => other.to_string(),
    }
}

fn parse_metadata_from_comment(body: &str, marker: &str) -> Result<ReviewMetadata, String> {
    let marker_idx = body
        .find(marker)
        .ok_or_else(|| format!("missing expected marker `{marker}` in comment body"))?;
    let after_marker = &body[marker_idx + marker.len()..];
    let json_payload = extract_fenced_block(after_marker, "json")
        .ok_or_else(|| "missing fenced json metadata block after marker".to_string())?;
    serde_json::from_str::<ReviewMetadata>(json_payload)
        .map_err(|err| format!("failed to parse metadata JSON: {err}"))
}

fn extract_fenced_block<'a>(source: &'a str, language: &str) -> Option<&'a str> {
    let start_marker = format!("```{language}");
    let start = source.find(&start_marker)?;
    let after_start = &source[start + start_marker.len()..];
    let content = after_start.strip_prefix('\n').unwrap_or(after_start);
    let end = content.find("\n```")?;
    Some(content[..end].trim())
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
    use super::{
        extract_fenced_block, normalize_review_type, parse_metadata_from_comment, sha256_hex,
        truncate_excerpt,
    };

    #[test]
    fn test_extract_fenced_block_json() {
        let source = "```json\n{\"a\":1}\n```\n";
        let block = extract_fenced_block(source, "json").expect("json block");
        assert_eq!(block, "{\"a\":1}");
    }

    #[test]
    fn test_parse_metadata_from_comment() {
        let body = r#"
<!-- apm2-review-metadata:v1:security -->
```json
{
  "schema": "apm2.review.metadata.v1",
  "review_type": "security",
  "pr_number": 482,
  "head_sha": "0123456789abcdef0123456789abcdef01234567"
}
```
"#;
        let parsed = parse_metadata_from_comment(body, "<!-- apm2-review-metadata:v1:security -->")
            .expect("metadata");
        assert_eq!(parsed.review_type, "security");
        assert_eq!(parsed.pr_number, 482);
    }

    #[test]
    fn test_normalize_review_type() {
        assert_eq!(normalize_review_type("quality"), "code-quality");
        assert_eq!(normalize_review_type("code_quality"), "code-quality");
        assert_eq!(normalize_review_type("security"), "security");
    }

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
