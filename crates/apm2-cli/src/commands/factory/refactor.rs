//! Refactor Radar CLI commands.
//!
//! This module provides CLI commands for running the refactor radar,
//! which analyzes the codebase for maintenance recommendations.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use apm2_core::refactor_radar::{
    CircuitBreakerStatus, DEFAULT_BACKLOG_THRESHOLD, DEFAULT_MAX_RECOMMENDATIONS, Radar,
    RadarConfig,
};
use clap::{Args, Subcommand};

/// Refactor command group.
#[derive(Debug, Args)]
pub struct RefactorCommand {
    #[command(subcommand)]
    pub subcommand: RefactorSubcommand,
}

/// Refactor subcommands.
#[derive(Debug, Subcommand)]
pub enum RefactorSubcommand {
    /// Run the refactor radar analysis.
    Radar(RefactorRadarArgs),
}

/// Arguments for the `refactor radar` command.
#[derive(Debug, Args)]
pub struct RefactorRadarArgs {
    /// Time window for analysis (e.g., 7d, 30d).
    #[arg(long, default_value = "7d")]
    pub window: String,

    /// Maximum number of recommendations to output.
    #[arg(long, default_value_t = DEFAULT_MAX_RECOMMENDATIONS)]
    pub max_items: usize,

    /// Force output even if circuit breaker is tripped.
    #[arg(long, default_value = "false")]
    pub ignore_breaker: bool,

    /// Backlog threshold for circuit breaker.
    #[arg(long, default_value_t = DEFAULT_BACKLOG_THRESHOLD)]
    pub backlog_threshold: usize,

    /// Path to repository root.
    /// Defaults to current directory.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,

    /// Output format (yaml or json).
    #[arg(long, default_value = "yaml", value_parser = ["yaml", "json", "text"])]
    pub format: String,
}

/// Runs the Refactor command.
pub fn run_refactor(cmd: &RefactorCommand) -> Result<()> {
    match &cmd.subcommand {
        RefactorSubcommand::Radar(args) => run_refactor_radar(args),
    }
}

/// Parses a duration string like "7d", "30d", "14d".
fn parse_window(window: &str) -> Result<Duration> {
    let window = window.trim();

    // Support days format: "7d", "30d"
    if let Some(days_str) = window.strip_suffix('d') {
        let days: u64 = days_str
            .parse()
            .with_context(|| format!("Invalid day count in window: {window}"))?;
        return Ok(Duration::from_secs(days * 86400));
    }

    // Support weeks format: "1w", "2w"
    if let Some(weeks_str) = window.strip_suffix('w') {
        let weeks: u64 = weeks_str
            .parse()
            .with_context(|| format!("Invalid week count in window: {window}"))?;
        return Ok(Duration::from_secs(weeks * 7 * 86400));
    }

    bail!("Invalid window format: {window}. Use format like '7d' or '2w'");
}

/// Runs the `refactor radar` command.
pub fn run_refactor_radar(args: &RefactorRadarArgs) -> Result<()> {
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

    // Parse window duration
    let window = parse_window(&args.window)?;
    let window_days = window.as_secs() / 86400;

    // Build configuration
    let config = RadarConfig {
        window,
        max_recommendations: args.max_items,
        backlog_threshold: args.backlog_threshold,
        ignore_breaker: args.ignore_breaker,
        ..Default::default()
    };

    if args.format == "text" {
        println!("Refactor Radar Analysis");
        println!("  Repository: {}", repo_root.display());
        println!("  Window: {window_days} days");
        println!("  Max items: {}", args.max_items);
        println!(
            "  Backlog threshold: {} (ignore: {})",
            args.backlog_threshold, args.ignore_breaker
        );
        println!();
    }

    // Run the radar
    let radar = Radar::new(config);
    let result = radar.run(&repo_root).context("Radar analysis failed")?;

    // Output based on format
    match args.format.as_str() {
        "json" => {
            let output = serde_json::to_string_pretty(&result)?;
            println!("{output}");
        },
        "yaml" => {
            let output = serde_yaml::to_string(&result)?;
            println!("{output}");
        },
        _ => {
            // Circuit breaker status
            println!("Circuit Breaker:");
            match result.circuit_breaker.status {
                CircuitBreakerStatus::Ok => {
                    println!("  Status: OK");
                },
                CircuitBreakerStatus::Tripped => {
                    println!("  Status: TRIPPED");
                    if result.circuit_breaker.ignored {
                        println!("  (Override: --ignore-breaker flag used)");
                    }
                },
            }
            println!(
                "  Current backlog: {} / {} threshold",
                result.circuit_breaker.current_backlog, result.circuit_breaker.threshold
            );
            println!();

            // Recommendations
            if result.recommendations.is_empty() {
                if result.circuit_breaker.is_blocking() {
                    println!(
                        "Recommendations suspended due to high backlog ({} open tickets).",
                        result.circuit_breaker.current_backlog
                    );
                    println!("Use --ignore-breaker to force output.");
                } else {
                    println!("No recommendations generated.");
                    println!("  Total signals analyzed: {}", result.total_signals);
                }
            } else {
                println!(
                    "Recommendations ({} of {} signals):",
                    result.recommendations.len(),
                    result.total_signals
                );
                println!();

                for rec in &result.recommendations {
                    println!(
                        "  #{} [{:?}] {}",
                        rec.priority,
                        rec.severity,
                        rec.source_path.display()
                    );
                    println!("     Type: {}", rec.signal_type);
                    println!("     Rationale: {}", rec.rationale);
                    println!("     Action: {}", rec.suggested_action);
                    println!(
                        "     Suggested ticket: {} ({})",
                        rec.suggested_ticket.title, rec.suggested_ticket.ticket_type
                    );
                    println!();
                }
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_window_days() {
        let d = parse_window("7d").unwrap();
        assert_eq!(d.as_secs(), 7 * 86400);

        let d = parse_window("30d").unwrap();
        assert_eq!(d.as_secs(), 30 * 86400);

        let d = parse_window("1d").unwrap();
        assert_eq!(d.as_secs(), 86400);
    }

    #[test]
    fn test_parse_window_weeks() {
        let d = parse_window("1w").unwrap();
        assert_eq!(d.as_secs(), 7 * 86400);

        let d = parse_window("2w").unwrap();
        assert_eq!(d.as_secs(), 14 * 86400);
    }

    #[test]
    fn test_parse_window_invalid() {
        assert!(parse_window("invalid").is_err());
        assert!(parse_window("7x").is_err());
        assert!(parse_window("").is_err());
    }

    #[test]
    fn test_parse_window_whitespace() {
        let d = parse_window("  7d  ").unwrap();
        assert_eq!(d.as_secs(), 7 * 86400);
    }
}
