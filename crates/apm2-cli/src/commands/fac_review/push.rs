//! Lean `run_push` pipeline: git push → create/update PR → enable auto-merge.

use std::path::Path;
use std::process::Command;

use crate::commands::fac_pr::{GitHubPrClient, PrListArgs};
use crate::exit_codes::codes as exit_codes;

// ── Ticket YAML parsing ─────────────────────────────────────────────────────

/// Minimal ticket metadata extracted from a ticket YAML file.
struct TicketMeta {
    id: String,
    title: String,
    in_scope: Vec<String>,
    rationale: String,
}

/// Parse a ticket YAML file and extract metadata for PR title/body.
fn parse_ticket_yaml(path: &Path) -> Result<TicketMeta, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read ticket YAML: {e}"))?;
    let doc: serde_yaml::Value =
        serde_yaml::from_str(&content).map_err(|e| format!("failed to parse ticket YAML: {e}"))?;

    let meta = doc
        .get("ticket_meta")
        .ok_or_else(|| "ticket YAML missing `ticket_meta` key".to_string())?;

    let ticket = meta
        .get("ticket")
        .ok_or_else(|| "ticket YAML missing `ticket_meta.ticket` key".to_string())?;

    let id = ticket
        .get("id")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("UNKNOWN")
        .to_string();

    let title = ticket
        .get("title")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("Untitled")
        .to_string();

    let scope = meta.get("scope");
    let in_scope = scope
        .and_then(|s| s.get("in_scope"))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(serde_yaml::Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    let rationale = meta
        .get("rationale")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();

    Ok(TicketMeta {
        id,
        title,
        in_scope,
        rationale,
    })
}

/// Build a PR title from ticket metadata: `{id}: {title}`.
fn build_pr_title(meta: &TicketMeta) -> String {
    format!("{}: {}", meta.id, meta.title)
}

/// Build a PR body from ticket metadata as Markdown.
fn build_pr_body(meta: &TicketMeta) -> String {
    use std::fmt::Write as _;
    let mut body = String::new();
    if !meta.in_scope.is_empty() {
        body.push_str("## Scope\n\n");
        for item in &meta.in_scope {
            let _ = writeln!(body, "- {item}");
        }
        body.push('\n');
    }
    if !meta.rationale.is_empty() {
        body.push_str("## Rationale\n\n");
        body.push_str(&meta.rationale);
        body.push('\n');
    }
    body
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

    // Parse ticket metadata if provided.
    let ticket_meta = ticket.map(parse_ticket_yaml).transpose();
    let ticket_meta = match ticket_meta {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    let client = match GitHubPrClient::new(repo) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("ERROR: failed to initialize forge provider: {error}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    // Step 2: create or update PR.
    let existing_pr = match client.list(&PrListArgs {
        head: Some(branch.clone()),
        ..PrListArgs::default()
    }) {
        Ok(entries) => entries.first().map(|e| e.number),
        Err(e) => {
            eprintln!("ERROR: failed to list PRs: {e}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    let pr_number = if let Some(pr_num) = existing_pr {
        // PR exists — update body if ticket metadata available.
        if let Some(ref meta) = ticket_meta {
            let title = build_pr_title(meta);
            let body = build_pr_body(meta);
            if let Err(e) = client.update_pr(pr_num, &title, &body) {
                eprintln!("WARNING: {e}");
            } else {
                eprintln!("fac push: updated PR #{pr_num}");
            }
        }
        pr_num
    } else {
        // No existing PR — create one.
        let (title, body) = ticket_meta.as_ref().map_or_else(
            || (branch.clone(), String::new()),
            |meta| (build_pr_title(meta), build_pr_body(meta)),
        );
        match client.create_pr(&title, &body, &branch, "main") {
            Ok(num) => {
                eprintln!("fac push: created PR #{num}");
                num
            },
            Err(e) => {
                eprintln!("ERROR: {e}");
                return exit_codes::GENERIC_ERROR;
            },
        }
    };

    // Step 3: enable auto-merge (now properly propagates errors).
    if let Err(e) = client.auto_merge(pr_number) {
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

    let child = Command::new(&exe_path)
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
        .map_err(|e| format!("failed to spawn pipeline process: {e}"))?;

    let pid = child.id();
    // Drop child handle to detach — the process continues in background.
    drop(child);

    eprintln!(
        "fac push: pipeline spawned (pid={pid}, log={})",
        log_path.display()
    );
    Ok(())
}
