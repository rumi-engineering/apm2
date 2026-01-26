//! RFC Framer CLI commands.
//!
//! This module provides CLI commands for framing RFCs from PRD requirements
//! and CCP artifacts. The RFC framer generates a complete RFC skeleton with
//! CCP grounding for traceability.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use apm2_core::rfc_framer::{RfcFrameOptions, frame_rfc};
use clap::{Args, Subcommand};

/// RFC command group.
#[derive(Debug, Args)]
pub struct RfcCommand {
    #[command(subcommand)]
    pub subcommand: RfcSubcommand,
}

/// RFC subcommands.
#[derive(Debug, Subcommand)]
pub enum RfcSubcommand {
    /// Frame an RFC from Impact Map and CCP artifacts.
    Frame(RfcFrameArgs),
}

/// Arguments for the `rfc frame` command.
#[derive(Debug, Args)]
pub struct RfcFrameArgs {
    /// PRD identifier (e.g., "PRD-0005").
    #[arg(long, required = true)]
    pub prd: String,

    /// RFC identifier (e.g., "RFC-0011").
    #[arg(long, required = true)]
    pub rfc: String,

    /// Path to repository root.
    /// Defaults to current directory.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,

    /// Force overwrite if RFC already exists.
    #[arg(long, default_value = "false")]
    pub force: bool,

    /// Dry run mode - compute but don't write output.
    #[arg(long, default_value = "false")]
    pub dry_run: bool,

    /// Skip path validation against CCP (not recommended).
    #[arg(long, default_value = "false")]
    pub skip_validation: bool,

    /// Output format (text or json).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// Runs the RFC command.
pub fn run_rfc(cmd: &RfcCommand) -> Result<()> {
    match &cmd.subcommand {
        RfcSubcommand::Frame(args) => run_rfc_frame(args),
    }
}

/// Runs the `rfc frame` command.
pub fn run_rfc_frame(args: &RfcFrameArgs) -> Result<()> {
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

    // Validate PRD ID format (basic validation)
    if !args.prd.starts_with("PRD-") {
        bail!(
            "Invalid PRD identifier format: '{}'. Expected format: PRD-XXXX",
            args.prd
        );
    }

    // Validate RFC ID format (basic validation)
    if !args.rfc.starts_with("RFC-") {
        bail!(
            "Invalid RFC identifier format: '{}'. Expected format: RFC-XXXX",
            args.rfc
        );
    }

    let options = RfcFrameOptions {
        force: args.force,
        dry_run: args.dry_run,
        skip_validation: args.skip_validation,
    };

    if args.format == "text" {
        if args.dry_run {
            println!("RFC Frame (dry run)");
        } else {
            println!("RFC Frame");
        }
        println!("  PRD: {}", args.prd);
        println!("  RFC: {}", args.rfc);
        println!("  Repository: {}", repo_root.display());
        println!("  Force: {}", args.force);
        if args.skip_validation {
            println!("  WARNING: Path validation skipped");
        }
        println!();
    }

    // Frame the RFC
    let result =
        frame_rfc(&repo_root, &args.prd, &args.rfc, &options).context("Failed to frame RFC")?;

    if args.format == "json" {
        // Output JSON result
        let output = serde_json::json!({
            "success": true,
            "rfc_id": result.frame.rfc_id,
            "prd_id": result.frame.prd_id,
            "title": result.frame.title,
            "ccp_grounding": {
                "ccp_index_ref": result.ccp_grounding.ccp_index_ref,
                "ccp_index_hash": result.ccp_grounding.ccp_index_hash,
                "impact_map_ref": result.ccp_grounding.impact_map_ref,
                "component_count": result.ccp_grounding.component_references.len()
            },
            "sections_generated": result.frame.sections.len(),
            "output_dir": result.output_dir.display().to_string(),
            "dry_run": args.dry_run
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Output text result
        if args.dry_run {
            println!("RFC framing completed (dry run - no files written)");
        } else {
            println!("RFC framing completed successfully");
        }
        println!();
        println!("RFC Summary:");
        println!("  RFC ID: {}", result.frame.rfc_id);
        println!("  Title: {}", result.frame.title);
        println!("  Sections: {}", result.frame.sections.len());
        println!();
        println!("CCP Grounding:");
        println!("  Index hash: {}", result.ccp_grounding.ccp_index_hash);
        println!(
            "  Components: {}",
            result.ccp_grounding.component_references.len()
        );
        for comp in &result.ccp_grounding.component_references {
            println!("    - {}: {}", comp.id, comp.rationale);
        }

        if !args.dry_run {
            println!();
            println!("Output files:");
            for section in &result.frame.sections {
                println!(
                    "  {}/{}",
                    result.output_dir.display(),
                    section.section_type.filename()
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_prd_format_validation() {
        let temp_dir = TempDir::new().unwrap();

        let args = RfcFrameArgs {
            prd: "INVALID".to_string(),
            rfc: "RFC-0001".to_string(),
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            dry_run: true,
            skip_validation: true,
            format: "text".to_string(),
        };

        let result = run_rfc_frame(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid PRD identifier")
        );
    }

    #[test]
    fn test_rfc_format_validation() {
        let temp_dir = TempDir::new().unwrap();

        let args = RfcFrameArgs {
            prd: "PRD-0001".to_string(),
            rfc: "INVALID".to_string(),
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            dry_run: true,
            skip_validation: true,
            format: "text".to_string(),
        };

        let result = run_rfc_frame(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid RFC identifier")
        );
    }

    #[test]
    fn test_nonexistent_repo_root() {
        let args = RfcFrameArgs {
            prd: "PRD-0001".to_string(),
            rfc: "RFC-0001".to_string(),
            repo_root: Some(PathBuf::from("/nonexistent/path")),
            force: false,
            dry_run: true,
            skip_validation: true,
            format: "text".to_string(),
        };

        let result = run_rfc_frame(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_repo_root_is_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        std::fs::write(&file_path, "content").unwrap();

        let args = RfcFrameArgs {
            prd: "PRD-0001".to_string(),
            rfc: "RFC-0001".to_string(),
            repo_root: Some(file_path),
            force: false,
            dry_run: true,
            skip_validation: true,
            format: "text".to_string(),
        };

        let result = run_rfc_frame(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a directory"));
    }
}
