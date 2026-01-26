//! Implementation of the `start-ticket` command.
//!
//! This command sets up the development environment for the next unblocked
//! ticket:
//! - Scans ticket YAML files to find pending tickets
//! - Derives ticket status from git state (merged PRs, existing branches)
//! - Creates a worktree and branch for the selected ticket
//! - Outputs context needed to implement the ticket
//!
//! # Usage
//!
//! - `cargo xtask start-ticket` - Find earliest unblocked ticket globally
//! - `cargo xtask start-ticket RFC-0001` - Filter to specific RFC
//! - `cargo xtask start-ticket TCK-00049` - Start specific ticket

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

use crate::ticket_status::{
    CompletedTicketsResult, get_completed_tickets, get_in_progress_tickets,
};
use crate::util::main_worktree;

/// Type of target specified for start-ticket command.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetType {
    /// No target - find earliest unblocked ticket globally
    None,
    /// RFC ID (e.g., "RFC-0001") - filter to specific RFC
    Rfc(String),
    /// Ticket ID (e.g., "TCK-00049") - start specific ticket
    Ticket(String),
}

/// Parse the target argument to determine what type it is.
fn parse_target(target: Option<&str>) -> TargetType {
    match target {
        None => TargetType::None,
        Some(s) if s.starts_with("RFC-") && s.len() == 8 => TargetType::Rfc(s.to_string()),
        Some(s) if s.starts_with("TCK-") && s.len() == 9 => TargetType::Ticket(s.to_string()),
        Some(s) => {
            // Try to be helpful with common mistakes
            if s.starts_with("RFC-") {
                eprintln!("Warning: RFC ID should be RFC-XXXX format (4 digits)");
            } else if s.starts_with("TCK-") {
                eprintln!("Warning: Ticket ID should be TCK-XXXXX format (5 digits)");
            }
            // Default to treating it as an RFC ID for backwards compatibility
            TargetType::Rfc(s.to_string())
        },
    }
}

/// Minimal ticket info parsed from YAML.
#[derive(Debug)]
struct TicketInfo {
    id: String,
    title: String,
    rfc_id: String,
    dependencies: Vec<String>,
    status: Option<String>,
}

/// Start work on the next unblocked ticket.
///
/// This function:
/// 1. Scans all ticket YAML files
/// 2. Derives status from git state (merged PRs = completed, branches = in
///    progress)
/// 3. Finds tickets with all dependencies completed and no branch yet
/// 4. Creates a worktree and branch for the first unblocked ticket
/// 5. Outputs context for implementation
///
/// # Arguments
///
/// * `target` - Optional RFC ID (RFC-XXXX), ticket ID (TCK-XXXXX), or None
/// * `print_path_only` - If true, only print the worktree path (for scripting)
///
/// # Errors
///
/// Returns an error if:
/// - No pending tickets are found
/// - All pending tickets are blocked by incomplete dependencies
/// - Worktree or branch creation fails
pub fn run(target: Option<&str>, print_path_only: bool) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;
    let main_worktree_path = main_worktree(&sh)?;

    // Parse target type
    let target_type = parse_target(target);

    // Scan all tickets
    let tickets_dir = main_worktree_path.join("documents/work/tickets");
    let tickets = scan_tickets(&tickets_dir)?;

    // Get ticket status from git state
    let github_completed = match get_completed_tickets(&sh) {
        CompletedTicketsResult::Success(tickets) => tickets,
        CompletedTicketsResult::NetworkError(msg) => {
            eprintln!("Warning: {msg}");
            eprintln!("         Using empty completed set - may re-select completed tickets.");
            eprintln!();
            std::collections::HashSet::new()
        },
    };

    // Merge GitHub completions with local status overrides
    let local_completed = get_locally_completed_tickets(&tickets);
    let completed: std::collections::HashSet<String> =
        github_completed.union(&local_completed).cloned().collect();

    let in_progress =
        get_in_progress_tickets(&sh, &completed).context("Failed to get in-progress tickets")?;

    // Find the ticket to work on based on target type
    let ticket: &TicketInfo = match &target_type {
        TargetType::Ticket(ticket_id) => {
            // Find specific ticket
            let ticket = tickets
                .iter()
                .find(|t| &t.id == ticket_id)
                .with_context(|| format!("Ticket {ticket_id} not found"))?;

            // Check if already completed or in progress
            if completed.contains(&ticket.id) {
                bail!("Ticket {ticket_id} is already completed.");
            }
            if in_progress.contains(&ticket.id) {
                bail!("Ticket {ticket_id} is already in progress.");
            }

            // Warn if dependencies are not met (but proceed anyway)
            let unmet_deps: Vec<&String> = ticket
                .dependencies
                .iter()
                .filter(|dep| !completed.contains(*dep))
                .collect();
            if !unmet_deps.is_empty() {
                eprintln!(
                    "Warning: Ticket {ticket_id} has unmet dependencies: {}",
                    unmet_deps
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                eprintln!("Proceeding anyway as explicitly requested.");
            }

            ticket
        },
        TargetType::Rfc(rfc_id) => {
            // Filter to specific RFC
            let unblocked: Vec<&TicketInfo> = tickets
                .iter()
                .filter(|t| &t.rfc_id == rfc_id)
                .filter(|t| !completed.contains(&t.id) && !in_progress.contains(&t.id))
                .filter(|t| t.dependencies.iter().all(|dep| completed.contains(dep)))
                .collect();

            if unblocked.is_empty() {
                let pending_count = tickets
                    .iter()
                    .filter(|t| &t.rfc_id == rfc_id)
                    .filter(|t| !completed.contains(&t.id) && !in_progress.contains(&t.id))
                    .count();

                if pending_count == 0 {
                    println!("All tickets for {rfc_id} are complete or in progress!");
                    return Ok(());
                }

                bail!(
                    "No unblocked tickets found for {rfc_id}.\n\
                     {pending_count} ticket(s) are pending but blocked by dependencies."
                );
            }

            unblocked[0]
        },
        TargetType::None => {
            // Find earliest unblocked ticket globally
            let unblocked: Vec<&TicketInfo> = tickets
                .iter()
                .filter(|t| !completed.contains(&t.id) && !in_progress.contains(&t.id))
                .filter(|t| t.dependencies.iter().all(|dep| completed.contains(dep)))
                .collect();

            if unblocked.is_empty() {
                let pending_count = tickets
                    .iter()
                    .filter(|t| !completed.contains(&t.id) && !in_progress.contains(&t.id))
                    .count();

                if pending_count == 0 {
                    println!("All tickets are complete or in progress!");
                    return Ok(());
                }

                bail!(
                    "No unblocked tickets found.\n\
                     {pending_count} ticket(s) are pending but blocked by dependencies."
                );
            }

            unblocked[0]
        },
    };

    if print_path_only {
        // Just print the worktree path for scripting
        let worktree_path = main_worktree_path
            .parent()
            .unwrap_or(&main_worktree_path)
            .join(format!("apm2-{}", ticket.id));
        println!("{}", worktree_path.display());
        return Ok(());
    }

    // Display ticket info
    if ticket.rfc_id.is_empty() {
        println!("Starting ticket {}", ticket.id);
    } else {
        println!("Starting ticket {} for {}", ticket.id, ticket.rfc_id);
    }
    println!("Title: {}", ticket.title);
    println!();

    // Create branch name (with or without RFC based on ticket's rfc_id)
    let branch_name = if ticket.rfc_id.is_empty() {
        format!("ticket/{}", ticket.id)
    } else {
        format!("ticket/{}/{}", ticket.rfc_id, ticket.id)
    };

    // Check if branch already exists
    let branch_exists = cmd!(sh, "git branch --list {branch_name}")
        .read()
        .context("Failed to check if branch exists")?;

    let branch_exists = !branch_exists.trim().is_empty();

    // Check if remote branch exists
    let remote_branch_exists = cmd!(sh, "git ls-remote --heads origin {branch_name}")
        .read()
        .context("Failed to check remote branch")?;

    let remote_branch_exists = !remote_branch_exists.trim().is_empty();

    // Determine worktree path
    let worktree_path = main_worktree_path
        .parent()
        .unwrap_or(&main_worktree_path)
        .join(format!("apm2-{}", ticket.id));

    // Check if worktree already exists
    let worktree_exists = worktree_path.exists();

    if worktree_exists {
        println!("Worktree already exists at {}", worktree_path.display());
        println!("Removing existing worktree...");
        cmd!(sh, "git worktree remove --force {worktree_path}")
            .run()
            .context("Failed to remove existing worktree")?;
    }

    // Create the branch and worktree
    if branch_exists {
        println!("Branch '{branch_name}' already exists locally, creating worktree...");
        cmd!(sh, "git worktree add {worktree_path} {branch_name}")
            .run()
            .context("Failed to create worktree for existing branch")?;
    } else if remote_branch_exists {
        println!("Branch '{branch_name}' exists on remote, creating worktree...");
        cmd!(sh, "git fetch origin {branch_name}")
            .run()
            .context("Failed to fetch remote branch")?;
        cmd!(sh, "git worktree add {worktree_path} {branch_name}")
            .run()
            .context("Failed to create worktree for remote branch")?;
    } else {
        println!("Creating new branch '{branch_name}' and worktree...");
        cmd!(sh, "git worktree add -b {branch_name} {worktree_path}")
            .run()
            .context("Failed to create worktree with new branch")?;
    }

    println!();
    println!("Worktree created at: {}", worktree_path.display());
    println!();

    // Output context for implementation
    print_context(&main_worktree_path, ticket);

    Ok(())
}

/// Scan all ticket YAML files and parse minimal info.
fn scan_tickets(tickets_dir: &PathBuf) -> Result<Vec<TicketInfo>> {
    let mut tickets = Vec::new();

    let entries = fs::read_dir(tickets_dir).with_context(|| {
        format!(
            "Failed to read tickets directory: {}",
            tickets_dir.display()
        )
    })?;

    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "yaml") {
            if let Some(ticket) = parse_ticket_yaml(&path)? {
                tickets.push(ticket);
            }
        }
    }

    // Sort by ticket ID for deterministic ordering
    tickets.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(tickets)
}

/// Get tickets marked as completed locally via status field.
///
/// This allows overriding GitHub PR detection for tickets whose PRs
/// used incorrect branch naming (e.g., TCK-00035 merged via TCK-00034 branch).
fn get_locally_completed_tickets(tickets: &[TicketInfo]) -> std::collections::HashSet<String> {
    tickets
        .iter()
        .filter(|ticket| {
            ticket
                .status
                .as_deref()
                .is_some_and(is_local_completion_status)
        })
        .map(|t| t.id.clone())
        .collect()
}

fn is_local_completion_status(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_uppercase().as_str(),
        "COMPLETED" | "DONE" | "CANCELLED" | "CANCELED"
    )
}

/// Parse minimal ticket info from a YAML file.
///
/// Uses simple string parsing to avoid adding a YAML parser dependency.
fn parse_ticket_yaml(path: &PathBuf) -> Result<Option<TicketInfo>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read ticket file: {}", path.display()))?;

    // Extract ticket ID
    let id = extract_yaml_value(&content, "id:")
        .with_context(|| format!("Missing ticket ID in {}", path.display()))?;

    // Only process TCK-XXXXX format tickets
    if !id.starts_with("TCK-") {
        return Ok(None);
    }

    // Extract other fields
    let title = extract_yaml_value(&content, "title:").unwrap_or_default();
    let rfc_id = extract_yaml_value(&content, "rfc_id:").unwrap_or_default();
    let status = extract_yaml_value(&content, "status:");

    // Extract dependencies
    let dependencies = extract_dependencies(&content);

    Ok(Some(TicketInfo {
        id,
        title,
        rfc_id,
        dependencies,
        status,
    }))
}

/// Extract a simple YAML value by key.
fn extract_yaml_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            let value = rest.trim();
            // Remove quotes if present
            let value = value.trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Extract ticket dependencies from YAML content.
fn extract_dependencies(content: &str) -> Vec<String> {
    let mut deps = Vec::new();
    let mut in_dependencies = false;
    let mut in_tickets = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("dependencies:") {
            in_dependencies = true;
            continue;
        }

        if in_dependencies && trimmed.starts_with("tickets:") {
            in_tickets = true;
            continue;
        }

        // Exit dependencies section when we hit another top-level key
        if in_dependencies
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && !trimmed.is_empty()
        {
            break;
        }

        // Parse ticket_id entries
        if in_tickets && trimmed.starts_with("- ticket_id:") {
            let value = trimmed["- ticket_id:".len()..].trim();
            let value = value.trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                deps.push(value.to_string());
            }
        }
    }

    deps
}

/// Print context information for implementing the ticket.
fn print_context(main_worktree: &Path, ticket: &TicketInfo) {
    println!("=== Implementation Context ===");
    println!();

    // Ticket details
    println!("Ticket: {} - {}", ticket.id, ticket.title);
    if !ticket.rfc_id.is_empty() {
        println!("RFC: {}", ticket.rfc_id);
    }
    println!();

    // Ticket file
    let ticket_yaml = main_worktree.join(format!("documents/work/tickets/{}.yaml", ticket.id));

    println!("Ticket file:");
    println!("  - {}", ticket_yaml.display());
    println!();

    // RFC files (only if ticket has an RFC)
    if !ticket.rfc_id.is_empty() {
        let rfc_dir = main_worktree.join(format!("documents/rfcs/{}", ticket.rfc_id));
        if rfc_dir.exists() {
            println!("RFC documentation:");
            if let Ok(entries) = fs::read_dir(&rfc_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path
                        .extension()
                        .is_some_and(|ext| ext == "yaml" || ext == "md")
                    {
                        println!("  - {}", path.display());
                    }
                }
            }
            println!();
        }
    }

    // Dependencies
    if !ticket.dependencies.is_empty() {
        println!("Dependencies (all COMPLETED):");
        for dep in &ticket.dependencies {
            println!("  - {dep}");
        }
        println!();
    }

    // Implementation guidance
    println!("Next steps:");
    println!("  1. Read the ticket YAML file for scope, plan, and criteria");
    if ticket.rfc_id.is_empty() {
        println!("  2. Look at existing implementations in xtask/src/tasks/");
        println!("  3. Implement the feature with tests");
        println!("  4. Run: cargo xtask check (once implemented)");
        println!("  5. Commit: cargo xtask commit \"<message>\" (once implemented)");
    } else {
        println!("  2. Read RFC design decisions for patterns to follow");
        println!("  3. Look at existing implementations in xtask/src/tasks/");
        println!("  4. Implement the feature with tests");
        println!("  5. Run: cargo xtask check (once implemented)");
        println!("  6. Commit: cargo xtask commit \"<message>\" (once implemented)");
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_yaml_value() {
        let content = r#"
ticket:
    id: "TCK-00030"
    title: "Implement start-ticket command"
    status: "PENDING"
"#;

        assert_eq!(
            extract_yaml_value(content, "id:"),
            Some("TCK-00030".to_string())
        );
        assert_eq!(
            extract_yaml_value(content, "title:"),
            Some("Implement start-ticket command".to_string())
        );
        assert_eq!(
            extract_yaml_value(content, "status:"),
            Some("PENDING".to_string())
        );
        assert_eq!(extract_yaml_value(content, "nonexistent:"), None);
    }

    #[test]
    fn test_extract_yaml_value_without_quotes() {
        let content = "status: PENDING";
        assert_eq!(
            extract_yaml_value(content, "status:"),
            Some("PENDING".to_string())
        );
    }

    #[test]
    fn test_extract_yaml_value_single_quotes() {
        let content = "id: 'TCK-00001'";
        assert_eq!(
            extract_yaml_value(content, "id:"),
            Some("TCK-00001".to_string())
        );
    }

    #[test]
    fn test_extract_dependencies() {
        let content = r#"
ticket_meta:
  dependencies:
    tickets:
      - ticket_id: "TCK-00026"
      - ticket_id: "TCK-00027"
  definition_of_done:
    evidence_ids: []
"#;

        let deps = extract_dependencies(content);
        assert_eq!(deps, vec!["TCK-00026", "TCK-00027"]);
    }

    #[test]
    fn test_extract_dependencies_empty() {
        let content = r"
ticket_meta:
  dependencies:
    tickets: []
  definition_of_done:
    evidence_ids: []
";

        let deps = extract_dependencies(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_extract_dependencies_no_section() {
        let content = r#"
ticket_meta:
  ticket:
    id: "TCK-00001"
"#;

        let deps = extract_dependencies(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_get_locally_completed_tickets_accepts_done_cancelled() {
        let tickets = vec![
            TicketInfo {
                id: "TCK-00001".to_string(),
                title: String::new(),
                rfc_id: String::new(),
                dependencies: Vec::new(),
                status: Some("DONE".to_string()),
            },
            TicketInfo {
                id: "TCK-00002".to_string(),
                title: String::new(),
                rfc_id: String::new(),
                dependencies: Vec::new(),
                status: Some("CANCELLED".to_string()),
            },
            TicketInfo {
                id: "TCK-00003".to_string(),
                title: String::new(),
                rfc_id: String::new(),
                dependencies: Vec::new(),
                status: Some("IN_PROGRESS".to_string()),
            },
        ];

        let completed = get_locally_completed_tickets(&tickets);
        assert!(completed.contains("TCK-00001"));
        assert!(completed.contains("TCK-00002"));
        assert!(!completed.contains("TCK-00003"));
    }

    #[test]
    fn test_parse_target_none() {
        assert_eq!(parse_target(None), TargetType::None);
    }

    #[test]
    fn test_parse_target_rfc() {
        assert_eq!(
            parse_target(Some("RFC-0001")),
            TargetType::Rfc("RFC-0001".to_string())
        );
        assert_eq!(
            parse_target(Some("RFC-9999")),
            TargetType::Rfc("RFC-9999".to_string())
        );
    }

    #[test]
    fn test_parse_target_ticket() {
        assert_eq!(
            parse_target(Some("TCK-00049")),
            TargetType::Ticket("TCK-00049".to_string())
        );
        assert_eq!(
            parse_target(Some("TCK-00001")),
            TargetType::Ticket("TCK-00001".to_string())
        );
    }

    #[test]
    fn test_parse_target_invalid_rfc_format() {
        // Too short - treated as RFC for backwards compatibility
        assert_eq!(
            parse_target(Some("RFC-01")),
            TargetType::Rfc("RFC-01".to_string())
        );
    }

    #[test]
    fn test_parse_target_invalid_ticket_format() {
        // Too short - treated as RFC for backwards compatibility
        assert_eq!(
            parse_target(Some("TCK-001")),
            TargetType::Rfc("TCK-001".to_string())
        );
    }
}
