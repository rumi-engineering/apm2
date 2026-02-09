//! Lean `run_push` pipeline: git push → create/update PR → enable auto-merge.

use std::path::Path;
use std::process::Command;

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

    // Step 2: create or update PR.
    let pr_number = find_existing_pr(repo, &branch);
    let pr_number = if pr_number == 0 {
        // No existing PR — create one.
        let (title, body) = ticket_meta.as_ref().map_or_else(
            || (branch.clone(), String::new()),
            |meta| (build_pr_title(meta), build_pr_body(meta)),
        );
        match create_pr(repo, &title, &body) {
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
        // PR exists — update body if ticket metadata available.
        if let Some(ref meta) = ticket_meta {
            let title = build_pr_title(meta);
            let body = build_pr_body(meta);
            if let Err(e) = update_pr(repo, pr_number, &title, &body) {
                eprintln!("WARNING: {e}");
            } else {
                eprintln!("fac push: updated PR #{pr_number}");
            }
        }
        pr_number
    };

    // Step 3: enable auto-merge.
    if let Err(e) = enable_auto_merge(repo, pr_number) {
        eprintln!("WARNING: auto-merge enable failed: {e}");
    } else {
        eprintln!("fac push: auto-merge enabled on PR #{pr_number}");
    }

    eprintln!("fac push: done (PR #{pr_number})");
    exit_codes::SUCCESS
}
