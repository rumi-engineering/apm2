//! Lean `run_push` pipeline: git push → blocking gates → PR/update → dispatch.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::dispatch::dispatch_single_review;
use super::evidence::{EvidenceGateResult, run_evidence_gates};
use super::pr_body::{GateResult, sync_gate_status_to_pr};
use super::types::{DispatchReviewResult, ReviewKind};
use super::{github_projection, projection_store};
use crate::exit_codes::codes as exit_codes;

const REQUIRED_TCK_FORMAT_MESSAGE: &str = "Required format: include `TCK-12345` in the branch name (recommended: `ticket/RFC-0018/TCK-12345`) or in the worktree directory name (example: `apm2-TCK-12345`).";

/// Extract `TCK-xxxxx` from arbitrary text.
fn extract_tck_from_text(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    if bytes.len() < 9 {
        return None;
    }

    for idx in 0..=bytes.len() - 9 {
        if &bytes[idx..idx + 4] != b"TCK-" {
            continue;
        }

        let digits = &bytes[idx + 4..idx + 9];
        if !digits.iter().all(u8::is_ascii_digit) {
            continue;
        }

        if idx + 9 < bytes.len() && bytes[idx + 9].is_ascii_digit() {
            continue;
        }

        let matched = std::str::from_utf8(&bytes[idx..idx + 9]).ok()?;
        return Some(matched.to_string());
    }

    None
}

/// Resolve TCK id from branch first, then worktree directory name.
fn resolve_tck_id(branch: &str, worktree_dir: &Path) -> Result<String, String> {
    if let Some(tck) = extract_tck_from_text(branch) {
        return Ok(tck);
    }

    let worktree_name = worktree_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if let Some(tck) = extract_tck_from_text(worktree_name) {
        return Ok(tck);
    }

    Err(format!(
        "could not derive TCK from branch `{branch}` or worktree `{}`. {REQUIRED_TCK_FORMAT_MESSAGE}",
        worktree_dir.display()
    ))
}

fn resolve_repo_root() -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to resolve repository root: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to resolve repository root via git: {}",
            stderr.trim()
        ));
    }

    let repo_root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if repo_root.is_empty() {
        return Err("git returned empty repository root".to_string());
    }

    Ok(PathBuf::from(repo_root))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitSummary {
    short_sha: String,
    message: String,
}

fn parse_commit_history(raw: &str) -> Vec<CommitSummary> {
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let (short_sha, message) = trimmed.split_once('\t')?;
            let short_sha = short_sha.trim();
            let message = message.trim();
            if short_sha.is_empty() || message.is_empty() {
                return None;
            }
            Some(CommitSummary {
                short_sha: short_sha.to_string(),
                message: message.to_string(),
            })
        })
        .collect()
}

fn resolve_commit_history_base_ref(remote: &str) -> Result<String, String> {
    let candidate = format!("{remote}/main");
    let candidate_commit = format!("{candidate}^{{commit}}");
    let remote_status = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", &candidate_commit])
        .status()
        .map_err(|err| format!("failed to resolve commit history base ref: {err}"))?;
    if remote_status.success() {
        return Ok(candidate);
    }

    let local_status = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", "main^{commit}"])
        .status()
        .map_err(|err| format!("failed to resolve commit history base ref: {err}"))?;
    if local_status.success() {
        return Ok("main".to_string());
    }

    Err(format!(
        "failed to resolve commit history base ref; neither `{remote}/main` nor `main` exists"
    ))
}

fn collect_commit_history(remote: &str, branch: &str) -> Result<Vec<CommitSummary>, String> {
    let base_ref = resolve_commit_history_base_ref(remote)?;
    let range = format!("{base_ref}..{branch}");
    let output = Command::new("git")
        .args(["log", "--format=%h%x09%s", "--reverse", &range])
        .output()
        .map_err(|err| format!("failed to collect commit history for `{range}`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to collect commit history for `{range}`: {}",
            stderr.trim()
        ));
    }

    let history = parse_commit_history(&String::from_utf8_lossy(&output.stdout));
    if !history.is_empty() {
        return Ok(history);
    }

    let head_output = Command::new("git")
        .args(["log", "-1", "--format=%h%x09%s", branch])
        .output()
        .map_err(|err| format!("failed to collect HEAD commit summary for `{branch}`: {err}"))?;
    if !head_output.status.success() {
        let stderr = String::from_utf8_lossy(&head_output.stderr);
        return Err(format!(
            "failed to collect HEAD commit summary for `{branch}`: {}",
            stderr.trim()
        ));
    }

    let fallback = parse_commit_history(&String::from_utf8_lossy(&head_output.stdout));
    if fallback.is_empty() {
        return Err(format!(
            "no commits found for branch `{branch}` while building PR description history"
        ));
    }
    Ok(fallback)
}

fn ticket_path_for_tck(repo_root: &Path, tck: &str) -> PathBuf {
    repo_root
        .join("documents")
        .join("work")
        .join("tickets")
        .join(format!("{tck}.yaml"))
}

fn load_ticket_body(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read ticket body at {}: {err}", path.display()))
}

fn load_ticket_title(path: &Path, body: &str) -> Result<String, String> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(body)
        .map_err(|err| format!("failed to parse ticket YAML at {}: {err}", path.display()))?;

    let Some(title) = parsed
        .get("ticket_meta")
        .and_then(|value| value.get("ticket"))
        .and_then(|value| value.get("title"))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(format!(
            "missing `ticket_meta.ticket.title` in {}",
            path.display()
        ));
    };

    Ok(title.to_string())
}

fn render_ticket_body_markdown(
    body: &str,
    commit_history: &[CommitSummary],
) -> Result<String, String> {
    let mut parsed: serde_yaml::Value = serde_yaml::from_str(body)
        .map_err(|err| format!("failed to parse ticket YAML for PR body rendering: {err}"))?;

    let history_entries = commit_history
        .iter()
        .map(|entry| {
            let mut item = serde_yaml::Mapping::new();
            item.insert(
                serde_yaml::Value::String("short_sha".to_string()),
                serde_yaml::Value::String(entry.short_sha.clone()),
            );
            item.insert(
                serde_yaml::Value::String("message".to_string()),
                serde_yaml::Value::String(entry.message.clone()),
            );
            serde_yaml::Value::Mapping(item)
        })
        .collect::<Vec<_>>();

    let root = parsed
        .as_mapping_mut()
        .ok_or_else(|| "ticket YAML root must be a mapping".to_string())?;
    let metadata_key = serde_yaml::Value::String("fac_push_metadata".to_string());
    let mut metadata_mapping = match root.remove(&metadata_key) {
        Some(serde_yaml::Value::Mapping(value)) => value,
        Some(_) | None => serde_yaml::Mapping::new(),
    };
    metadata_mapping.insert(
        serde_yaml::Value::String("commit_history".to_string()),
        serde_yaml::Value::Sequence(history_entries),
    );
    root.insert(metadata_key, serde_yaml::Value::Mapping(metadata_mapping));

    let mut rendered = serde_yaml::to_string(&parsed)
        .map_err(|err| format!("failed to render PR description YAML: {err}"))?;
    if let Some(stripped) = rendered.strip_prefix("---\n") {
        rendered = stripped.to_string();
    }
    let normalized = rendered.trim_end_matches('\n');
    Ok(format!("```yaml\n{normalized}\n```"))
}

fn validate_ticket_path_matches_tck(ticket_path: &Path, tck: &str) -> Result<(), String> {
    let Some(stem) = ticket_path.file_stem().and_then(|value| value.to_str()) else {
        return Err(format!(
            "invalid --ticket path `{}`; expected filename `{tck}.yaml`",
            ticket_path.display()
        ));
    };

    if stem != tck {
        return Err(format!(
            "--ticket path `{}` does not match derived TCK `{tck}`; expected filename `{tck}.yaml`",
            ticket_path.display()
        ));
    }

    Ok(())
}

#[derive(Debug)]
struct PrMetadata {
    title: String,
    body: String,
    ticket_path: PathBuf,
}

fn resolve_pr_metadata(
    branch: &str,
    worktree_dir: &Path,
    repo_root: &Path,
    commit_history: &[CommitSummary],
    ticket: Option<&Path>,
) -> Result<PrMetadata, String> {
    let tck_id = resolve_tck_id(branch, worktree_dir)?;
    if let Some(ticket_path) = ticket {
        validate_ticket_path_matches_tck(ticket_path, &tck_id)?;
    }

    let canonical_ticket_path = ticket_path_for_tck(repo_root, &tck_id);
    let raw_body = load_ticket_body(&canonical_ticket_path)?;
    let ticket_title = load_ticket_title(&canonical_ticket_path, &raw_body)?;
    let body = render_ticket_body_markdown(&raw_body, commit_history)?;
    Ok(PrMetadata {
        title: format!("{tck_id}: {ticket_title}"),
        body,
        ticket_path: canonical_ticket_path,
    })
}

// ── PR helpers ───────────────────────────────────────────────────────────────

/// Look up an existing PR number for the given branch, or return 0 if none.
fn find_existing_pr(repo: &str, branch: &str) -> u32 {
    match github_projection::find_pr_for_branch(repo, branch) {
        Ok(Some(number)) => number,
        _ => 0,
    }
}

/// Create a new PR and return the PR number on success.
fn create_pr(repo: &str, title: &str, body: &str) -> Result<u32, String> {
    github_projection::create_pr(repo, title, body)
}

/// Update an existing PR's title and body.
fn update_pr(repo: &str, pr_number: u32, title: &str, body: &str) -> Result<(), String> {
    github_projection::update_pr(repo, pr_number, title, body)
}

/// Enable auto-merge (squash) on a PR.
fn enable_auto_merge(repo: &str, pr_number: u32) -> Result<(), String> {
    github_projection::enable_auto_merge(repo, pr_number)
}

fn ensure_evidence_gates_pass_with<F>(
    workspace_root: &Path,
    sha: &str,
    mut run_gates_fn: F,
) -> Result<Vec<EvidenceGateResult>, String>
where
    F: FnMut(&Path, &str) -> Result<(bool, Vec<EvidenceGateResult>), String>,
{
    let (passed, results) = run_gates_fn(workspace_root, sha)?;
    if passed {
        return Ok(results);
    }

    let failed_gates = results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| result.gate_name.as_str())
        .collect::<Vec<_>>();
    let failed_summary = if failed_gates.is_empty() {
        "unknown".to_string()
    } else {
        failed_gates.join(",")
    };
    Err(format!(
        "evidence gates failed for sha={sha}; failing gates: {failed_summary}"
    ))
}

fn run_blocking_evidence_gates(
    workspace_root: &Path,
    sha: &str,
) -> Result<Vec<EvidenceGateResult>, String> {
    ensure_evidence_gates_pass_with(workspace_root, sha, |root, head_sha| {
        run_evidence_gates(root, head_sha, None, None)
    })
}

fn dispatch_reviews_with<F>(
    repo: &str,
    pr_number: u32,
    sha: &str,
    mut dispatch_fn: F,
) -> Result<(), String>
where
    F: FnMut(&str, u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
{
    let dispatch_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    for kind in [ReviewKind::Security, ReviewKind::Quality] {
        let result = dispatch_fn(repo, pr_number, kind, sha, dispatch_epoch)
            .map_err(|err| format!("failed to dispatch {} review: {err}", kind.as_str()))?;
        eprintln!(
            "fac push: dispatched {} review (mode={}{})",
            result.review_type,
            result.mode,
            result
                .pid
                .map_or_else(String::new, |pid| format!(", pid={pid}")),
        );
    }

    Ok(())
}

// ── run_push entry point ─────────────────────────────────────────────────────

pub fn run_push(repo: &str, remote: &str, branch: Option<&str>, ticket: Option<&Path>) -> u8 {
    // Resolve branch name.
    let branch = if let Some(b) = branch {
        b.to_string()
    } else {
        let output = Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output();
        match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => {
                eprintln!("ERROR: failed to resolve current branch");
                return exit_codes::GENERIC_ERROR;
            },
        }
    };

    // Resolve HEAD SHA for logging.
    let sha = match Command::new("git").args(["rev-parse", "HEAD"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            eprintln!("ERROR: failed to resolve HEAD SHA");
            return exit_codes::GENERIC_ERROR;
        },
    };

    eprintln!("fac push: sha={sha} branch={branch}");

    // Resolve metadata deterministically from TCK identity.
    let worktree_dir = match std::env::current_dir() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("ERROR: failed to resolve current worktree path: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };
    let repo_root = match resolve_repo_root() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("ERROR: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };
    let commit_history = match collect_commit_history(remote, &branch) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("ERROR: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    let metadata =
        match resolve_pr_metadata(&branch, &worktree_dir, &repo_root, &commit_history, ticket) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("ERROR: {err}");
                eprintln!(
                    "ERROR: expected ticket file under documents/work/tickets/TCK-xxxxx.yaml"
                );
                return exit_codes::GENERIC_ERROR;
            },
        };
    eprintln!(
        "fac push: metadata title={} body={}",
        metadata.title,
        metadata.ticket_path.display()
    );
    let local_pr_hint = projection_store::load_branch_identity(repo, &branch)
        .ok()
        .flatten()
        .map(|identity| identity.pr_number);

    // Step 1: git push (always force; local branch truth is authoritative).
    let push_output = Command::new("git")
        .args(["push", "--force", remote, &branch])
        .output();
    match push_output {
        Ok(o) if o.status.success() => {
            eprintln!("fac push: git push --force succeeded");
        },
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!("ERROR: git push --force failed: {stderr}");
            return exit_codes::GENERIC_ERROR;
        },
        Err(e) => {
            eprintln!("ERROR: failed to execute git push --force: {e}");
            return exit_codes::GENERIC_ERROR;
        },
    }

    // Step 2: run evidence gates synchronously.
    eprintln!("fac push: running evidence gates (blocking)");
    let gate_results = match run_blocking_evidence_gates(&worktree_dir, &sha) {
        Ok(results) => results,
        Err(err) => {
            eprintln!("ERROR: {err}");
            return exit_codes::GENERIC_ERROR;
        },
    };
    eprintln!("fac push: evidence gates PASSED");

    // Step 3: create or update PR (projection best-effort; local truth remains
    // authoritative).
    let pr_number = find_existing_pr(repo, &branch);
    let pr_number = if pr_number == 0 {
        match create_pr(repo, &metadata.title, &metadata.body) {
            Ok(num) => {
                eprintln!("fac push: created PR #{num}");
                num
            },
            Err(e) => {
                if let Some(local_pr) = local_pr_hint {
                    eprintln!(
                        "WARNING: failed to create PR projection ({e}); continuing with local PR mapping #{local_pr}"
                    );
                    local_pr
                } else {
                    eprintln!("ERROR: {e}");
                    eprintln!(
                        "ERROR: unable to resolve PR mapping for branch `{branch}`; projection bootstrap requires GitHub availability at least once"
                    );
                    return exit_codes::GENERIC_ERROR;
                }
            },
        }
    } else {
        if let Err(err) = update_pr(repo, pr_number, &metadata.title, &metadata.body) {
            eprintln!(
                "WARNING: failed to update PR projection for #{pr_number}: {err} (continuing with local authoritative flow)"
            );
        }
        eprintln!("fac push: using PR #{pr_number}");
        pr_number
    };
    if let Err(err) = projection_store::save_identity_with_context(repo, pr_number, &sha, "push") {
        eprintln!("WARNING: failed to persist local projection identity: {err}");
    }
    if let Err(err) =
        projection_store::save_pr_body_snapshot(repo, pr_number, &metadata.body, "push")
    {
        eprintln!("WARNING: failed to persist local PR body snapshot: {err}");
    }

    // Step 3.5: sync gate status section to PR body (best-effort).
    let gate_status_rows = gate_results
        .iter()
        .map(|result| GateResult {
            name: result.gate_name.clone(),
            passed: result.passed,
            duration_secs: result.duration_secs,
        })
        .collect::<Vec<_>>();
    if let Err(err) = sync_gate_status_to_pr(repo, pr_number, gate_status_rows, &sha) {
        eprintln!("WARNING: failed to sync gate status section in PR body: {err}");
    } else {
        eprintln!("fac push: synced gate status section in PR body for PR #{pr_number}");
    }

    // Step 4: enable auto-merge.
    if let Err(e) = enable_auto_merge(repo, pr_number) {
        eprintln!("WARNING: auto-merge enable failed: {e}");
    } else {
        eprintln!("fac push: auto-merge enabled on PR #{pr_number}");
    }

    // Step 5: dispatch reviews.
    if let Err(e) = dispatch_reviews_with(repo, pr_number, &sha, dispatch_single_review) {
        eprintln!("ERROR: {e}");
        eprintln!("  Use `apm2 fac restart --pr {pr_number}` to retry.");
        return exit_codes::GENERIC_ERROR;
    }

    eprintln!("fac push: done (PR #{pr_number})");
    eprintln!("  if review dispatch stalls: apm2 fac restart --pr {pr_number}");
    exit_codes::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn sample_commit_history() -> Vec<CommitSummary> {
        vec![
            CommitSummary {
                short_sha: "abc12345".to_string(),
                message: "first change".to_string(),
            },
            CommitSummary {
                short_sha: "def67890".to_string(),
                message: "second change".to_string(),
            },
        ]
    }

    fn parse_yaml_from_markdown_fence(markdown: &str) -> serde_yaml::Value {
        let content = markdown
            .strip_prefix("```yaml\n")
            .and_then(|value| value.strip_suffix("\n```"))
            .expect("yaml fence");
        serde_yaml::from_str(content).expect("valid yaml")
    }

    #[test]
    fn extract_tck_from_text_accepts_valid_pattern() {
        assert_eq!(
            extract_tck_from_text("ticket/RFC-0018/TCK-00412"),
            Some("TCK-00412".to_string())
        );
    }

    #[test]
    fn extract_tck_from_text_rejects_invalid_variants() {
        assert_eq!(extract_tck_from_text("ticket/rfc/TCK-412"), None);
        assert_eq!(extract_tck_from_text("ticket/rfc/tck-00412"), None);
        assert_eq!(extract_tck_from_text("ticket/rfc/TCK-004123"), None);
    }

    #[test]
    fn resolve_tck_id_prefers_branch() {
        let worktree = Path::new("/tmp/apm2-TCK-99999");
        let tck = resolve_tck_id("ticket/RFC-0018/TCK-00412", worktree)
            .expect("branch should provide tck");
        assert_eq!(tck, "TCK-00412");
    }

    #[test]
    fn resolve_tck_id_falls_back_to_worktree_name() {
        let worktree = Path::new("/tmp/apm2-TCK-00444");
        let tck = resolve_tck_id("feat/no-ticket", worktree).expect("worktree should provide tck");
        assert_eq!(tck, "TCK-00444");
    }

    #[test]
    fn resolve_tck_id_returns_actionable_error() {
        let worktree = Path::new("/tmp/apm2-no-ticket");
        let err = resolve_tck_id("feat/no-ticket", worktree).expect_err("should fail");
        assert!(err.contains("Required format"));
        assert!(err.contains("TCK-12345"));
    }

    #[test]
    fn ticket_path_for_tck_uses_canonical_location() {
        let path = ticket_path_for_tck(Path::new("/repo"), "TCK-00412");
        assert_eq!(
            path,
            PathBuf::from("/repo/documents/work/tickets/TCK-00412.yaml")
        );
    }

    #[test]
    fn validate_ticket_path_matches_tck_accepts_matching_filename() {
        let result = validate_ticket_path_matches_tck(
            Path::new("documents/work/tickets/TCK-00412.yaml"),
            "TCK-00412",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_ticket_path_matches_tck_rejects_mismatch() {
        let err = validate_ticket_path_matches_tck(
            Path::new("documents/work/tickets/TCK-00411.yaml"),
            "TCK-00412",
        )
        .expect_err("mismatch should fail");
        assert!(err.contains("does not match derived TCK"));
    }

    #[test]
    fn load_ticket_body_reads_raw_contents() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let ticket_path = temp_dir.path().join("TCK-00412.yaml");
        std::fs::write(
            &ticket_path,
            "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n",
        )
        .expect("write ticket");

        let content = load_ticket_body(&ticket_path).expect("load ticket body");
        assert_eq!(content, "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n");
    }

    #[test]
    fn load_ticket_title_reads_plain_title() {
        let ticket_path = Path::new("/repo/documents/work/tickets/TCK-00412.yaml");
        let body = "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n    title: \"Title Value\"\n";
        let title = load_ticket_title(ticket_path, body).expect("title should parse");
        assert_eq!(title, "Title Value");
    }

    #[test]
    fn load_ticket_title_fails_when_missing() {
        let ticket_path = Path::new("/repo/documents/work/tickets/TCK-00412.yaml");
        let body = "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n";
        let err = load_ticket_title(ticket_path, body).expect_err("missing title should fail");
        assert!(err.contains("ticket_meta.ticket.title"));
    }

    #[test]
    fn parse_commit_history_parses_short_sha_and_message() {
        let parsed = parse_commit_history("abc12345\tfirst change\ndef67890\tsecond change\n");
        assert_eq!(parsed, sample_commit_history());
    }

    #[test]
    fn render_ticket_body_markdown_includes_commit_history_metadata() {
        let rendered = render_ticket_body_markdown(
            "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n",
            &sample_commit_history(),
        )
        .expect("render ticket body");
        let yaml = parse_yaml_from_markdown_fence(&rendered);

        let ticket_id = yaml
            .get("ticket_meta")
            .and_then(|value| value.get("ticket"))
            .and_then(|value| value.get("id"))
            .and_then(serde_yaml::Value::as_str)
            .expect("ticket id");
        assert_eq!(ticket_id, "TCK-00412");

        let history = yaml
            .get("fac_push_metadata")
            .and_then(|value| value.get("commit_history"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("commit history");
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0]
                .get("short_sha")
                .and_then(serde_yaml::Value::as_str),
            Some("abc12345")
        );
        assert_eq!(
            history[0]
                .get("message")
                .and_then(serde_yaml::Value::as_str),
            Some("first change")
        );
    }

    #[test]
    fn resolve_pr_metadata_branch_tck_yields_title_and_markdown_body() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo_root = temp_dir.path();
        let tickets_dir = repo_root.join("documents/work/tickets");
        crate::commands::fac_permissions::ensure_dir_with_mode(&tickets_dir)
            .expect("create tickets dir");
        let ticket_path = tickets_dir.join("TCK-00412.yaml");
        let ticket_content = "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n    title: \"Any\"\n";
        fs::write(&ticket_path, ticket_content).expect("write ticket");

        let metadata = resolve_pr_metadata(
            "ticket/RFC-0018/TCK-00412",
            Path::new("/tmp/apm2-no-ticket"),
            repo_root,
            &sample_commit_history(),
            None,
        )
        .expect("resolve metadata");
        assert_eq!(metadata.title, "TCK-00412: Any");
        let yaml = parse_yaml_from_markdown_fence(&metadata.body);
        let history = yaml
            .get("fac_push_metadata")
            .and_then(|value| value.get("commit_history"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("commit history");
        assert_eq!(history.len(), 2);
        assert_eq!(metadata.ticket_path, ticket_path);
    }

    #[test]
    fn resolve_pr_metadata_uses_worktree_fallback() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo_root = temp_dir.path();
        let tickets_dir = repo_root.join("documents/work/tickets");
        crate::commands::fac_permissions::ensure_dir_with_mode(&tickets_dir)
            .expect("create tickets dir");
        let ticket_path = tickets_dir.join("TCK-00444.yaml");
        let ticket_content =
            "ticket_meta:\n  ticket:\n    id: \"TCK-00444\"\n    title: \"Fallback Title\"\n";
        fs::write(&ticket_path, ticket_content).expect("write ticket");

        let metadata = resolve_pr_metadata(
            "feat/no-ticket",
            Path::new("/tmp/apm2-TCK-00444"),
            repo_root,
            &sample_commit_history(),
            None,
        )
        .expect("resolve metadata");
        assert_eq!(metadata.title, "TCK-00444: Fallback Title");
        let yaml = parse_yaml_from_markdown_fence(&metadata.body);
        let history = yaml
            .get("fac_push_metadata")
            .and_then(|value| value.get("commit_history"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("commit history");
        assert_eq!(history.len(), 2);
        assert_eq!(metadata.ticket_path, ticket_path);
    }

    #[test]
    fn resolve_pr_metadata_rejects_ticket_mismatch() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo_root = temp_dir.path();
        let tickets_dir = repo_root.join("documents/work/tickets");
        crate::commands::fac_permissions::ensure_dir_with_mode(&tickets_dir)
            .expect("create tickets dir");
        fs::write(tickets_dir.join("TCK-00412.yaml"), "ticket_meta:\n").expect("write ticket");

        let err = resolve_pr_metadata(
            "ticket/RFC-0018/TCK-00412",
            Path::new("/tmp/apm2-no-ticket"),
            repo_root,
            &sample_commit_history(),
            Some(Path::new("documents/work/tickets/TCK-00411.yaml")),
        )
        .expect_err("mismatch should fail");
        assert!(err.contains("does not match derived TCK"));
    }

    #[test]
    fn resolve_pr_metadata_fails_when_canonical_ticket_missing() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo_root = temp_dir.path();
        let err = resolve_pr_metadata(
            "ticket/RFC-0018/TCK-00412",
            Path::new("/tmp/apm2-no-ticket"),
            repo_root,
            &sample_commit_history(),
            None,
        )
        .expect_err("missing ticket should fail");
        assert!(err.contains("failed to read ticket body"));
        assert!(err.contains("TCK-00412.yaml"));
    }

    #[test]
    fn ensure_evidence_gates_pass_with_accepts_pass_result() {
        let result =
            ensure_evidence_gates_pass_with(Path::new("/tmp"), "a".repeat(40).as_str(), |_, _| {
                Ok((true, Vec::new()))
            });
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_evidence_gates_pass_with_reports_failed_gate_names() {
        let result =
            ensure_evidence_gates_pass_with(Path::new("/tmp"), "b".repeat(40).as_str(), |_, _| {
                Ok((
                    false,
                    vec![
                        EvidenceGateResult {
                            gate_name: "rustfmt".to_string(),
                            passed: false,
                            duration_secs: 1,
                        },
                        EvidenceGateResult {
                            gate_name: "clippy".to_string(),
                            passed: true,
                            duration_secs: 2,
                        },
                        EvidenceGateResult {
                            gate_name: "doc".to_string(),
                            passed: false,
                            duration_secs: 3,
                        },
                    ],
                ))
            })
            .expect_err("expected failure");

        assert!(result.contains("rustfmt"));
        assert!(result.contains("doc"));
        assert!(!result.contains("clippy"));
    }

    #[test]
    fn dispatch_reviews_with_dispatches_security_then_quality() {
        let mut dispatched = Vec::new();
        let result = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "a".repeat(40).as_str(),
            |_, _, kind, _, _| {
                dispatched.push(kind.as_str().to_string());
                Ok(DispatchReviewResult {
                    review_type: kind.as_str().to_string(),
                    mode: "dispatched".to_string(),
                    run_state: "pending".to_string(),
                    run_id: None,
                    sequence_number: None,
                    terminal_reason: None,
                    pid: None,
                    unit: None,
                    log_file: None,
                })
            },
        );

        assert!(result.is_ok());
        assert_eq!(dispatched, vec!["security", "quality"]);
    }

    #[test]
    fn dispatch_reviews_with_fails_closed_on_dispatch_error() {
        let mut calls = 0usize;
        let err = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "b".repeat(40).as_str(),
            |_, _, kind, _, _| {
                calls += 1;
                if kind == ReviewKind::Security {
                    return Err("simulated failure".to_string());
                }
                Ok(DispatchReviewResult {
                    review_type: kind.as_str().to_string(),
                    mode: "dispatched".to_string(),
                    run_state: "pending".to_string(),
                    run_id: None,
                    sequence_number: None,
                    terminal_reason: None,
                    pid: None,
                    unit: None,
                    log_file: None,
                })
            },
        )
        .expect_err("expected dispatch failure");

        assert!(err.contains("failed to dispatch security review"));
        assert_eq!(calls, 1);
    }
}
