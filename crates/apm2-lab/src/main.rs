#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use apm2_lab::closure::{ClosureConfig, ClosureReducer};
use apm2_lab::harness::run_experiment;
use apm2_lab::ledger::LabLedger;
use apm2_lab::spec::LabSpec;
use clap::{Parser, Subcommand};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "apm2-lab")]
#[command(about = "PASM theory laboratory harness")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run one experiment instance.
    Run {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        seed: u64,
        #[arg(long)]
        condition: Option<String>,
    },
    /// Run multiple seeds and aggregate summaries.
    Sweep {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        seeds: String,
        #[arg(long)]
        conditions: Option<String>,
    },
    /// Re-evaluate closure from a recorded ledger.
    Replay {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        spec: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            spec,
            seed,
            condition,
        } => {
            let spec = LabSpec::load(spec)?;
            let summary = run_experiment(spec, condition.as_deref(), seed).await?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        },
        Command::Sweep {
            spec,
            seeds,
            conditions,
        } => {
            let spec = LabSpec::load(&spec)?;
            let seed_values = parse_csv_u64(&seeds)?;
            if seed_values.is_empty() {
                anyhow::bail!("--seeds must include at least one value");
            }

            let condition_values: BTreeSet<String> = if let Some(csv) = conditions {
                csv.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            } else {
                spec.conditions.keys().cloned().collect()
            };

            if condition_values.is_empty() {
                anyhow::bail!("no conditions available for sweep");
            }

            let mut all = Vec::new();
            for condition in condition_values {
                for seed in &seed_values {
                    let summary = run_experiment(spec.clone(), Some(&condition), *seed)
                        .await
                        .with_context(|| format!("run seed {seed} condition {condition}"))?;
                    all.push(summary);
                }
            }

            let aggregate = SweepAggregate::from_runs(&all);
            println!("{}", serde_json::to_string_pretty(&aggregate)?);
        },
        Command::Replay { ledger, spec } => {
            let ledger = LabLedger::load_jsonl(ledger)?;
            let config = if let Some(path) = spec {
                let spec = LabSpec::load(path)?;
                ClosureConfig {
                    tau_compression_gain: spec.formation_policy.tau_compression_gain,
                    max_composite_size: spec.formation_policy.max_composite_size,
                    require_all_attestations: spec.formation_policy.require_all_attestations,
                }
            } else {
                ClosureConfig {
                    tau_compression_gain: 0.15,
                    max_composite_size: 8,
                    require_all_attestations: true,
                }
            };

            let reducer = ClosureReducer::new(config);
            let snapshot = reducer.evaluate(ledger.events())?;

            let report = ReplayReport {
                ledger_events: ledger.len(),
                admitted_work: snapshot.admitted_work_ids.len(),
                rejected_work: snapshot.rejected_work_ids.len(),
                active_composites: snapshot.active_composites.len(),
                pending_formations: snapshot.pending_formations,
                derived_events_if_replayed: snapshot.derived_events.len(),
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
        },
    }

    Ok(())
}

fn parse_csv_u64(input: &str) -> Result<Vec<u64>> {
    input
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<u64>()
                .with_context(|| format!("invalid seed '{part}'"))
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct ReplayReport {
    ledger_events: usize,
    admitted_work: usize,
    rejected_work: usize,
    active_composites: usize,
    pending_formations: usize,
    derived_events_if_replayed: usize,
}

#[derive(Debug, Serialize)]
struct SweepAggregate {
    runs: usize,
    formation_rate: f64,
    mean_total_score: f64,
    mean_compound_success_pre: f64,
    mean_compound_success_post: f64,
    mean_tokens: f64,
    mean_cli_calls: f64,
}

impl SweepAggregate {
    fn from_runs(runs: &[apm2_lab::metrics::RunSummary]) -> Self {
        let n = runs.len().max(1) as f64;
        let formation_rate = runs.iter().filter(|r| r.formation_occurred).count() as f64 / n;
        let mean_total_score = runs.iter().map(|r| r.total_score).sum::<f64>() / n;
        let mean_compound_success_pre = runs
            .iter()
            .map(|r| r.compound_success_rate_pre)
            .sum::<f64>()
            / n;
        let mean_compound_success_post = runs
            .iter()
            .map(|r| r.compound_success_rate_post)
            .sum::<f64>()
            / n;
        let mean_tokens = runs.iter().map(|r| r.total_tokens as f64).sum::<f64>() / n;
        let mean_cli_calls = runs.iter().map(|r| r.total_cli_calls as f64).sum::<f64>() / n;

        Self {
            runs: runs.len(),
            formation_rate,
            mean_total_score,
            mean_compound_success_pre,
            mean_compound_success_post,
            mean_tokens,
            mean_cli_calls,
        }
    }
}
