//! Implementation of the `start-ticket` command.
//!
//! This command sets up the development environment for the next unblocked
//! ticket:
//! - Scans ticket YAML files to find pending tickets for the RFC
//! - Filters to tickets with all dependencies completed
//! - Creates a worktree and branch for the selected ticket
//! - Outputs context needed to implement the ticket

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

use crate::util::main_worktree;

/// Minimal ticket info parsed from YAML.
#[derive(Debug)]
struct TicketInfo {
    id: String,
    title: String,
    status: String,
    rfc_id: String,
    dependencies: Vec<String>,
}

/// Start work on the next unblocked ticket for an RFC.
///
/// This function:
/// 1. Scans all ticket YAML files
/// 2. Filters to PENDING tickets for the given RFC
/// 3. Finds tickets with all dependencies COMPLETED
/// 4. Creates a worktree and branch for the first unblocked ticket
/// 5. Outputs context for implementation
///
/// # Arguments
///
/// * `rfc_id` - The RFC ID (e.g., "RFC-0002")
/// * `print_path_only` - If true, only print the worktree path (for scripting)
///
/// # Errors
///
/// Returns an error if:
/// - No pending tickets are found for the RFC
/// - All pending tickets are blocked by incomplete dependencies
/// - Worktree or branch creation fails
pub fn run(rfc_id: &str, print_path_only: bool) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;
    let main_worktree_path = main_worktree(&sh)?;

    // Validate RFC ID format
    if !rfc_id.starts_with("RFC-") || rfc_id.len() != 8 {
        bail!(
            "Invalid RFC ID format: '{rfc_id}'\n\
             Expected format: RFC-XXXX (e.g., RFC-0002)"
        );
    }

    // Scan all tickets
    let tickets_dir = main_worktree_path.join("documents/work/tickets");
    let tickets = scan_tickets(&tickets_dir)?;

    // Build set of completed ticket IDs
    let completed: HashSet<String> = tickets
        .iter()
        .filter(|t| t.status == "COMPLETED")
        .map(|t| t.id.clone())
        .collect();

    // Find pending tickets for this RFC with all dependencies completed
    let unblocked: Vec<&TicketInfo> = tickets
        .iter()
        .filter(|t| t.rfc_id == rfc_id && t.status == "PENDING")
        .filter(|t| t.dependencies.iter().all(|dep| completed.contains(dep)))
        .collect();

    if unblocked.is_empty() {
        // Check if there are any pending tickets at all
        let pending_count = tickets
            .iter()
            .filter(|t| t.rfc_id == rfc_id && t.status == "PENDING")
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

    // Take the first unblocked ticket (they're sorted by ID from scan)
    let ticket = unblocked[0];

    if print_path_only {
        // Just print the worktree path for scripting
        let worktree_path = main_worktree_path
            .parent()
            .unwrap_or(&main_worktree_path)
            .join(format!("apm2-{}", ticket.id));
        println!("{}", worktree_path.display());
        return Ok(());
    }

    println!("Starting ticket {} for {}", ticket.id, rfc_id);
    println!("Title: {}", ticket.title);
    println!();

    // Create branch name
    let branch_name = format!("ticket/{}/{}", rfc_id, ticket.id);

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
    print_context(&main_worktree_path, rfc_id, ticket);

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
    let status = extract_yaml_value(&content, "status:").unwrap_or_else(|| "PENDING".to_string());
    let rfc_id = extract_yaml_value(&content, "rfc_id:").unwrap_or_default();

    // Extract dependencies
    let dependencies = extract_dependencies(&content);

    Ok(Some(TicketInfo {
        id,
        title,
        status,
        rfc_id,
        dependencies,
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
fn print_context(main_worktree: &Path, rfc_id: &str, ticket: &TicketInfo) {
    println!("=== Implementation Context ===");
    println!();

    // Ticket details
    println!("Ticket: {} - {}", ticket.id, ticket.title);
    println!("RFC: {rfc_id}");
    println!();

    // Ticket files
    let ticket_yaml = main_worktree.join(format!("documents/work/tickets/{}.yaml", ticket.id));
    let ticket_md = main_worktree.join(format!("documents/work/tickets/{}.md", ticket.id));

    println!("Ticket files:");
    println!("  - {}", ticket_yaml.display());
    if ticket_md.exists() {
        println!("  - {}", ticket_md.display());
    }
    println!();

    // RFC files
    let rfc_dir = main_worktree.join(format!("documents/rfcs/{rfc_id}"));
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
    println!("  1. Read the ticket YAML and MD files for requirements");
    println!("  2. Read RFC design decisions for patterns to follow");
    println!("  3. Look at existing implementations in xtask/src/tasks/");
    println!("  4. Implement the feature with tests");
    println!("  5. Run: cargo xtask check (once implemented)");
    println!("  6. Commit: cargo xtask commit \"<message>\" (once implemented)");
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
}
