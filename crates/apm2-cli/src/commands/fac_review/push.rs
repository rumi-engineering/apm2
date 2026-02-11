//! Lean `run_push` pipeline: git push → create/update PR → enable auto-merge.

use std::path::{Path, PathBuf};
use std::process::Command;

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
    let output = Command::new("gh")
        .args([
            "pr",
            "list",
            "--repo",
            repo,
            "--head",
            branch,
            "--json",
            "number",
            "--jq",
            ".[0].number",
        ])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let num_str = String::from_utf8_lossy(&o.stdout).trim().to_string();
            num_str.parse::<u32>().unwrap_or(0)
        },
        _ => 0,
    }
}

/// Create a new PR and return the PR number on success.
fn create_pr(repo: &str, title: &str, body: &str) -> Result<u32, String> {
    let output = Command::new("gh")
        .args([
            "pr", "create", "--repo", repo, "--title", title, "--body", body, "--base", "main",
        ])
        .output()
        .map_err(|e| format!("failed to execute gh pr create: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gh pr create failed: {stderr}"));
    }

    // gh pr create prints the PR URL on stdout; extract the number.
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let pr_number = url
        .rsplit('/')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| format!("could not parse PR number from gh output: {url}"))?;

    Ok(pr_number)
}

/// Update an existing PR's title and body.
fn update_pr(repo: &str, pr_number: u32, title: &str, body: &str) -> Result<(), String> {
    let pr_ref = pr_number.to_string();
    let output = Command::new("gh")
        .args([
            "pr", "edit", &pr_ref, "--repo", repo, "--title", title, "--body", body,
        ])
        .output()
        .map_err(|e| format!("failed to execute gh pr edit: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gh pr edit failed: {stderr}"));
    }
    Ok(())
}

/// Enable auto-merge (squash) on a PR.
fn enable_auto_merge(repo: &str, pr_number: u32) -> Result<(), String> {
    let pr_ref = pr_number.to_string();
    let output = Command::new("gh")
        .args(["pr", "merge", &pr_ref, "--repo", repo, "--auto", "--squash"])
        .output()
        .map_err(|e| format!("failed to execute gh pr merge --auto: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Auto-merge may already be enabled — treat as non-fatal warning.
        eprintln!("WARNING: gh pr merge --auto: {stderr}");
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

    // Step 1: git push.
    let push_output = Command::new("git").args(["push", remote, &branch]).output();
    match push_output {
        Ok(o) if o.status.success() => {
            eprintln!("fac push: git push succeeded");
        },
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!("ERROR: git push failed: {stderr}");
            return exit_codes::GENERIC_ERROR;
        },
        Err(e) => {
            eprintln!("ERROR: failed to execute git push: {e}");
            return exit_codes::GENERIC_ERROR;
        },
    }

    // Step 2: create or update PR.
    let pr_number = find_existing_pr(repo, &branch);
    let pr_number = if pr_number == 0 {
        match create_pr(repo, &metadata.title, &metadata.body) {
            Ok(num) => {
                eprintln!("fac push: created PR #{num}");
                num
            },
            Err(e) => {
                eprintln!("ERROR: {e}");
                return exit_codes::GENERIC_ERROR;
            },
        }
    } else {
        if let Err(err) = update_pr(repo, pr_number, &metadata.title, &metadata.body) {
            eprintln!("ERROR: {err}");
            return exit_codes::GENERIC_ERROR;
        }
        eprintln!("fac push: updated PR #{pr_number}");
        pr_number
    };

    // Step 3: enable auto-merge.
    if let Err(e) = enable_auto_merge(repo, pr_number) {
        eprintln!("WARNING: auto-merge enable failed: {e}");
    } else {
        eprintln!("fac push: auto-merge enabled on PR #{pr_number}");
    }

    // Step 4: spawn background evidence+review pipeline.
    let pr_url = format!("https://github.com/{repo}/pull/{pr_number}");
    if let Err(e) = spawn_pipeline(repo, &pr_url, pr_number, &sha) {
        eprintln!("WARNING: pipeline spawn failed: {e}");
        eprintln!("  Use `apm2 fac restart --pr {pr_number}` to retry.");
    }

    let sha_short = &sha[..sha.len().min(8)];
    eprintln!("fac push: done (PR #{pr_number})");
    eprintln!("  pipeline log: ~/.apm2/pipeline_logs/pr{pr_number}-{sha_short}.log");
    eprintln!("  if pipeline fails: apm2 fac restart --pr {pr_number}");
    exit_codes::SUCCESS
}

// ── Background pipeline spawn ────────────────────────────────────────────────

/// Spawn `apm2 fac pipeline` as a detached background process.
fn spawn_pipeline(repo: &str, pr_url: &str, pr_number: u32, sha: &str) -> Result<(), String> {
    use std::fs::{self, OpenOptions};
    use std::io::ErrorKind;

    let exe_path = std::env::current_exe()
        .map_err(|e| format!("failed to resolve current executable: {e}"))?;
    let cwd = std::env::current_dir().map_err(|e| format!("failed to resolve cwd: {e}"))?;

    // Log to ~/.apm2/pipeline_logs/pr{N}-{sha_short}.log
    let home = super::types::apm2_home_dir()?;
    let log_dir = home.join("pipeline_logs");
    fs::create_dir_all(&log_dir)
        .map_err(|e| format!("failed to create pipeline log directory: {e}"))?;
    let sha_short = &sha[..sha.len().min(8)];
    let log_path = log_dir.join(format!("pr{pr_number}-{sha_short}.log"));

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("failed to open pipeline log {}: {e}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .map_err(|e| format!("failed to clone pipeline log handle: {e}"))?;

    // Use `setsid` to detach from the caller's session so the pipeline
    // survives shell teardown and can finish status/review projection updates.
    let mut setsid_cmd = Command::new("setsid");
    setsid_cmd
        .arg(&exe_path)
        .arg("fac")
        .arg("pipeline")
        .arg("--repo")
        .arg(repo)
        .arg("--pr-url")
        .arg(pr_url)
        .arg("--pr")
        .arg(pr_number.to_string())
        .arg("--sha")
        .arg(sha)
        .current_dir(&cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr));

    let child = match setsid_cmd.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            eprintln!(
                "WARNING: `setsid` not available; falling back to non-detached pipeline spawn"
            );

            let stdout = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .map_err(|e| {
                    format!("failed to reopen pipeline log {}: {e}", log_path.display())
                })?;
            let stderr = stdout
                .try_clone()
                .map_err(|e| format!("failed to clone pipeline log handle: {e}"))?;

            Command::new(&exe_path)
                .arg("fac")
                .arg("pipeline")
                .arg("--repo")
                .arg(repo)
                .arg("--pr-url")
                .arg(pr_url)
                .arg("--pr")
                .arg(pr_number.to_string())
                .arg("--sha")
                .arg(sha)
                .current_dir(cwd)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::from(stdout))
                .stderr(std::process::Stdio::from(stderr))
                .spawn()
                .map_err(|e| format!("failed to spawn pipeline process: {e}"))?
        },
        Err(err) => {
            return Err(format!(
                "failed to spawn detached pipeline process with setsid: {err}"
            ));
        },
    };

    let pid = child.id();
    // Drop child handle to detach — the process continues in background.
    drop(child);

    eprintln!(
        "fac push: pipeline spawned (pid={pid}, log={})",
        log_path.display()
    );
    Ok(())
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
        fs::create_dir_all(&tickets_dir).expect("create tickets dir");
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
        fs::create_dir_all(&tickets_dir).expect("create tickets dir");
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
        fs::create_dir_all(&tickets_dir).expect("create tickets dir");
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
}
