//! CCP (Code Context Protocol) CLI commands.
//!
//! This module provides CLI commands for building and managing CCP indexes,
//! which combine component atlas and crate graph into a unified,
//! content-addressed artifact.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use apm2_core::ccp::index::{CcpBuildOptions, build_ccp_index};
use clap::{Args, Subcommand};

/// CCP command group.
#[derive(Debug, Args)]
pub struct CcpCommand {
    #[command(subcommand)]
    pub subcommand: CcpSubcommand,
}

/// CCP subcommands.
#[derive(Debug, Subcommand)]
pub enum CcpSubcommand {
    /// Build the CCP index for a PRD.
    Build(CcpBuildArgs),
}

/// Arguments for the `ccp build` command.
#[derive(Debug, Args)]
pub struct CcpBuildArgs {
    /// PRD identifier (e.g., "PRD-0001").
    #[arg(long, required = true)]
    pub prd: String,

    /// Path to repository root.
    /// Defaults to current directory.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,

    /// Force rebuild even if index hash hasn't changed.
    #[arg(long, default_value = "false")]
    pub force: bool,

    /// Dry run mode - compute but don't write output.
    #[arg(long, default_value = "false")]
    pub dry_run: bool,

    /// Output format (text or json).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// Runs the CCP command.
pub fn run_ccp(cmd: &CcpCommand) -> Result<()> {
    match &cmd.subcommand {
        CcpSubcommand::Build(args) => run_ccp_build(args),
    }
}

/// Runs the `ccp build` command.
pub fn run_ccp_build(args: &CcpBuildArgs) -> Result<()> {
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

    let options = CcpBuildOptions {
        force: args.force,
        dry_run: args.dry_run,
    };

    if args.format == "text" {
        if args.dry_run {
            println!("CCP Index Build (dry run)");
        } else {
            println!("CCP Index Build");
        }
        println!("  PRD: {}", args.prd);
        println!("  Repository: {}", repo_root.display());
        println!("  Force: {}", args.force);
        println!();
    }

    // Build the CCP index
    let result =
        build_ccp_index(&repo_root, &args.prd, &options).context("Failed to build CCP index")?;

    if args.format == "json" {
        // Output JSON result
        let output = serde_json::json!({
            "success": true,
            "skipped": result.skipped,
            "prd_id": result.index.prd_id,
            "index_hash": result.index.index_hash,
            "component_count": result.index.component_count,
            "crate_count": result.index.crate_count,
            "edge_count": result.index.edge_count,
            "file_count": result.index.file_inventory.file_count,
            "total_size": result.index.file_inventory.total_size,
            "output_dir": result.output_dir.display().to_string(),
            "dry_run": args.dry_run,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Output text result
        if result.skipped {
            println!("Index unchanged - build skipped");
            println!("  Index hash: {}", result.index.index_hash);
        } else if args.dry_run {
            println!("Build completed (dry run - no files written)");
            println!();
            println!("Index Summary:");
            println!("  Hash: {}", result.index.index_hash);
            println!("  Components: {}", result.index.component_count);
            println!("  Crates: {}", result.index.crate_count);
            println!("  Edges: {}", result.index.edge_count);
            println!(
                "  Source files: {} ({} bytes)",
                result.index.file_inventory.file_count, result.index.file_inventory.total_size
            );
        } else {
            println!("Build completed successfully");
            println!();
            println!("Index Summary:");
            println!("  Hash: {}", result.index.index_hash);
            println!("  Components: {}", result.index.component_count);
            println!("  Crates: {}", result.index.crate_count);
            println!("  Edges: {}", result.index.edge_count);
            println!(
                "  Source files: {} ({} bytes)",
                result.index.file_inventory.file_count, result.index.file_inventory.total_size
            );
            println!();
            println!("Output files:");
            println!("  {}/ccp_index.json", result.output_dir.display());
            println!("  {}/component_atlas.yaml", result.output_dir.display());
            println!("  {}/crate_graph.yaml", result.output_dir.display());
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

        let args = CcpBuildArgs {
            prd: "INVALID".to_string(),
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            dry_run: true,
            format: "text".to_string(),
        };

        let result = run_ccp_build(&args);
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
        let args = CcpBuildArgs {
            prd: "PRD-0001".to_string(),
            repo_root: Some(PathBuf::from("/nonexistent/path")),
            force: false,
            dry_run: true,
            format: "text".to_string(),
        };

        let result = run_ccp_build(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_repo_root_is_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        std::fs::write(&file_path, "content").unwrap();

        let args = CcpBuildArgs {
            prd: "PRD-0001".to_string(),
            repo_root: Some(file_path),
            force: false,
            dry_run: true,
            format: "text".to_string(),
        };

        let result = run_ccp_build(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a directory"));
    }
}
