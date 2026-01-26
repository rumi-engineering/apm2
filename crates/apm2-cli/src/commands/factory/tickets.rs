//! Ticket Emitter CLI commands.
//!
//! This module provides CLI commands for emitting tickets from RFC
//! decomposition. The ticket emitter generates atomic, implementable
//! tickets with stable IDs and verification commands.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use apm2_core::ticket_emitter::{TicketEmitOptions, emit_tickets};
use clap::{Args, Subcommand};

/// Tickets command group.
#[derive(Debug, Args)]
pub struct TicketsCommand {
    #[command(subcommand)]
    pub subcommand: TicketsSubcommand,
}

/// Tickets subcommands.
#[derive(Debug, Subcommand)]
pub enum TicketsSubcommand {
    /// Emit tickets from an RFC's ticket decomposition.
    Emit(TicketsEmitArgs),
}

/// Arguments for the `tickets emit` command.
#[derive(Debug, Args)]
pub struct TicketsEmitArgs {
    /// RFC identifier (e.g., "RFC-0010").
    #[arg(long, required = true)]
    pub rfc: String,

    /// PRD identifier for CCP validation (optional).
    #[arg(long)]
    pub prd: Option<String>,

    /// Path to repository root.
    /// Defaults to current directory.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,

    /// Force overwrite if tickets already exist.
    #[arg(long, default_value = "false")]
    pub force: bool,

    /// Dry run mode - compute but don't write output.
    #[arg(long, default_value = "false")]
    pub dry_run: bool,

    /// Skip path validation (not recommended).
    #[arg(long, default_value = "false")]
    pub skip_validation: bool,

    /// Output format (text or json).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// Runs the tickets command.
pub fn run_tickets(cmd: &TicketsCommand) -> Result<()> {
    match &cmd.subcommand {
        TicketsSubcommand::Emit(args) => run_tickets_emit(args),
    }
}

/// Runs the `tickets emit` command.
pub fn run_tickets_emit(args: &TicketsEmitArgs) -> Result<()> {
    // Determine repo root
    let repo_root = match &args.repo_root {
        Some(path) => path.clone(),
        None => std::env::current_dir().context("Failed to get current directory")?,
    };

    // Validate repo root exists
    if !repo_root.exists() {
        bail!("Repository root does not exist: {}", repo_root.display());
    }

    // Validate repo root is a directory
    if !repo_root.is_dir() {
        bail!(
            "Repository root is not a directory: {}",
            repo_root.display()
        );
    }

    // Validate RFC ID format (basic validation)
    if !args.rfc.starts_with("RFC-") {
        bail!(
            "Invalid RFC identifier format: '{}'. Expected format: RFC-XXXX",
            args.rfc
        );
    }

    // Validate PRD ID format if provided
    if let Some(prd) = &args.prd {
        if !prd.starts_with("PRD-") {
            bail!("Invalid PRD identifier format: '{prd}'. Expected format: PRD-XXXX");
        }
    }

    let options = TicketEmitOptions {
        force: args.force,
        dry_run: args.dry_run,
        skip_validation: args.skip_validation,
        prd_id: args.prd.clone(),
    };

    if args.format == "text" {
        if args.dry_run {
            println!("Ticket Emission (dry run)");
        } else {
            println!("Ticket Emission");
        }
        println!("  RFC: {}", args.rfc);
        if let Some(prd) = &args.prd {
            println!("  PRD: {prd} (for CCP validation)");
        }
        println!("  Repository: {}", repo_root.display());
        println!("  Force: {}", args.force);
        if args.skip_validation {
            println!("  WARNING: Path validation skipped");
        }
        println!();
    }

    // Emit tickets
    let result = emit_tickets(&repo_root, &args.rfc, &options).context("Failed to emit tickets")?;

    if args.format == "json" {
        // Output JSON result
        let tickets_json: Vec<serde_json::Value> = result
            .tickets
            .iter()
            .map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "title": t.title,
                    "status": t.status,
                    "requirement_ids": t.requirement_ids,
                    "depends_on": t.depends_on,
                    "files_to_create": t.files_to_create.iter().map(|f| &f.path).collect::<Vec<_>>(),
                    "files_to_modify": t.files_to_modify.iter().map(|f| &f.path).collect::<Vec<_>>(),
                    "verification_commands": t.test_requirements.iter().map(|tr| &tr.verification_command).collect::<Vec<_>>()
                })
            })
            .collect();

        let output = serde_json::json!({
            "success": true,
            "rfc_id": result.rfc_id,
            "ticket_count": result.tickets.len(),
            "tickets": tickets_json,
            "output_dir": result.output_dir.display().to_string(),
            "dry_run": args.dry_run,
            "warnings": result.warnings
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Output text result
        if args.dry_run {
            println!("Ticket emission completed (dry run - no files written)");
        } else {
            println!("Ticket emission completed successfully");
        }
        println!();
        println!("Summary:");
        println!("  RFC ID: {}", result.rfc_id);
        println!("  Tickets: {}", result.tickets.len());
        println!();

        println!("Emitted Tickets:");
        for ticket in &result.tickets {
            println!("  {}: {}", ticket.id, ticket.title);
            if !ticket.depends_on.is_empty() {
                println!("    Depends on: {}", ticket.depends_on.join(", "));
            }
            println!("    Files to create: {}", ticket.files_to_create.len());
            println!("    Files to modify: {}", ticket.files_to_modify.len());
            println!(
                "    Verification commands: {}",
                ticket.test_requirements.len()
            );
        }

        if !result.warnings.is_empty() {
            println!();
            println!("Warnings:");
            for warning in &result.warnings {
                println!("  - {warning}");
            }
        }

        if !args.dry_run {
            println!();
            println!("Output directory: {}", result.output_dir.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_rfc_format_validation() {
        let temp_dir = TempDir::new().unwrap();

        let args = TicketsEmitArgs {
            rfc: "INVALID".to_string(),
            prd: None,
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            dry_run: true,
            skip_validation: true,
            format: "text".to_string(),
        };

        let result = run_tickets_emit(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid RFC identifier")
        );
    }

    #[test]
    fn test_prd_format_validation() {
        let temp_dir = TempDir::new().unwrap();

        let args = TicketsEmitArgs {
            rfc: "RFC-0001".to_string(),
            prd: Some("INVALID".to_string()),
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            dry_run: true,
            skip_validation: true,
            format: "text".to_string(),
        };

        let result = run_tickets_emit(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid PRD identifier")
        );
    }

    #[test]
    fn test_nonexistent_repo_root() {
        let args = TicketsEmitArgs {
            rfc: "RFC-0001".to_string(),
            prd: None,
            repo_root: Some(PathBuf::from("/nonexistent/path")),
            force: false,
            dry_run: true,
            skip_validation: true,
            format: "text".to_string(),
        };

        let result = run_tickets_emit(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_repo_root_is_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        std::fs::write(&file_path, "content").unwrap();

        let args = TicketsEmitArgs {
            rfc: "RFC-0001".to_string(),
            prd: None,
            repo_root: Some(file_path),
            force: false,
            dry_run: true,
            skip_validation: true,
            format: "text".to_string(),
        };

        let result = run_tickets_emit(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a directory"));
    }
}
