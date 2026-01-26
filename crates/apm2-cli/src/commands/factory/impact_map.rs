//! Impact Map CLI commands.
//!
//! This module provides CLI commands for building impact maps, which
//! map PRD requirements to CCP components.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use apm2_core::impact_map::{ImpactMapBuildOptions, build_impact_map};
use clap::{Args, Subcommand};

/// Impact Map command group.
#[derive(Debug, Args)]
pub struct ImpactMapCommand {
    #[command(subcommand)]
    pub subcommand: ImpactMapSubcommand,
}

/// Impact Map subcommands.
#[derive(Debug, Subcommand)]
pub enum ImpactMapSubcommand {
    /// Build the impact map for a PRD.
    Build(ImpactMapBuildArgs),
}

/// Arguments for the `impact-map build` command.
#[derive(Debug, Args)]
pub struct ImpactMapBuildArgs {
    /// PRD identifier (e.g., "PRD-0005").
    #[arg(long, required = true)]
    pub prd: String,

    /// Path to repository root.
    /// Defaults to current directory.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,

    /// Force rebuild even if inputs haven't changed.
    #[arg(long, default_value = "false")]
    pub force: bool,

    /// Dry run mode - compute but don't write output.
    #[arg(long, default_value = "false")]
    pub dry_run: bool,

    /// Output format (text or json).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// Runs the Impact Map command.
pub fn run_impact_map(cmd: &ImpactMapCommand) -> Result<()> {
    match &cmd.subcommand {
        ImpactMapSubcommand::Build(args) => run_impact_map_build(args),
    }
}

/// Runs the `impact-map build` command.
pub fn run_impact_map_build(args: &ImpactMapBuildArgs) -> Result<()> {
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

    let options = ImpactMapBuildOptions {
        force: args.force,
        dry_run: args.dry_run,
    };

    if args.format == "text" {
        if args.dry_run {
            println!("Impact Map Build (dry run)");
        } else {
            println!("Impact Map Build");
        }
        println!("  PRD: {}", args.prd);
        println!("  Repository: {}", repo_root.display());
        println!("  Force: {}", args.force);
        println!();
    }

    // Build the impact map
    let result =
        build_impact_map(&repo_root, &args.prd, &options).context("Failed to build impact map")?;

    if args.format == "json" {
        // Output JSON result
        let output = serde_json::json!({
            "success": true,
            "skipped": result.skipped,
            "prd_id": result.impact_map.prd_id,
            "content_hash": result.impact_map.content_hash,
            "ccp_index_hash": result.impact_map.ccp_index_hash,
            "summary": {
                "total_requirements": result.impact_map.summary.total_requirements,
                "high_confidence_matches": result.impact_map.summary.high_confidence_matches,
                "needs_review": result.impact_map.summary.needs_review,
                "duplication_risks": result.impact_map.summary.duplication_risks,
                "net_new_count": result.impact_map.summary.net_new_count,
            },
            "output_dir": result.output_dir.display().to_string(),
            "dry_run": args.dry_run,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Output text result
        if result.skipped {
            println!("Impact map unchanged - build skipped");
            println!("  Content hash: {}", result.impact_map.content_hash);
        } else if args.dry_run {
            println!("Build completed (dry run - no files written)");
            println!();
            println!("Impact Map Summary:");
            println!("  Content hash: {}", result.impact_map.content_hash);
            println!("  CCP index hash: {}", result.impact_map.ccp_index_hash);
            println!(
                "  Total requirements: {}",
                result.impact_map.summary.total_requirements
            );
            println!(
                "  High confidence matches: {}",
                result.impact_map.summary.high_confidence_matches
            );
            println!("  Needs review: {}", result.impact_map.summary.needs_review);
            println!(
                "  Duplication risks: {}",
                result.impact_map.summary.duplication_risks
            );
            println!(
                "  Net-new requirements: {}",
                result.impact_map.summary.net_new_count
            );
        } else {
            println!("Build completed successfully");
            println!();
            println!("Impact Map Summary:");
            println!("  Content hash: {}", result.impact_map.content_hash);
            println!("  CCP index hash: {}", result.impact_map.ccp_index_hash);
            println!(
                "  Total requirements: {}",
                result.impact_map.summary.total_requirements
            );
            println!(
                "  High confidence matches: {}",
                result.impact_map.summary.high_confidence_matches
            );
            println!("  Needs review: {}", result.impact_map.summary.needs_review);
            println!(
                "  Duplication risks: {}",
                result.impact_map.summary.duplication_risks
            );
            println!(
                "  Net-new requirements: {}",
                result.impact_map.summary.net_new_count
            );
            println!();
            println!("Output files:");
            println!("  {}/impact_map.yaml", result.output_dir.display());

            // Show duplication risks if any
            if !result.impact_map.adjudication.duplication_risks.is_empty() {
                println!();
                println!("Duplication Risks:");
                for risk in &result.impact_map.adjudication.duplication_risks {
                    println!(
                        "  {} [{:?}]: {}",
                        risk.requirement_id, risk.severity, risk.rationale
                    );
                }
            }

            // Show net-new requirements if any
            if !result
                .impact_map
                .adjudication
                .net_new_requirements
                .is_empty()
            {
                println!();
                println!("Net-New Requirements:");
                for net_new in &result.impact_map.adjudication.net_new_requirements {
                    println!("  {}: {}", net_new.requirement_id, net_new.reason);
                }
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

        let args = ImpactMapBuildArgs {
            prd: "INVALID".to_string(),
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            dry_run: true,
            format: "text".to_string(),
        };

        let result = run_impact_map_build(&args);
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
        let args = ImpactMapBuildArgs {
            prd: "PRD-0001".to_string(),
            repo_root: Some(PathBuf::from("/nonexistent/path")),
            force: false,
            dry_run: true,
            format: "text".to_string(),
        };

        let result = run_impact_map_build(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_repo_root_is_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        std::fs::write(&file_path, "content").unwrap();

        let args = ImpactMapBuildArgs {
            prd: "PRD-0001".to_string(),
            repo_root: Some(file_path),
            force: false,
            dry_run: true,
            format: "text".to_string(),
        };

        let result = run_impact_map_build(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a directory"));
    }
}
