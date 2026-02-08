use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::event::WorkType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenedWorkMetric {
    pub id: String,
    pub work_type: WorkType,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTickMetric {
    pub id: String,
    pub budget: u64,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickMetric {
    pub tick: u64,
    pub work_opened: Vec<OpenedWorkMetric>,
    pub work_admitted: Vec<String>,
    pub work_failed: Vec<String>,
    pub agents: Vec<AgentTickMetric>,
    pub formations_pending: usize,
    pub composites_active: usize,
    pub cumulative_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunSummary {
    pub seed: u64,
    pub condition: String,
    pub formation_occurred: bool,
    pub formation_tick: Option<u64>,
    pub formation_rationale: Option<String>,
    pub compound_success_rate_pre: f64,
    pub compound_success_rate_post: f64,
    pub total_score: f64,
    pub total_tokens: u64,
    pub total_cli_calls: u64,
}

pub struct MetricsWriter {
    tick_writer: BufWriter<File>,
}

impl MetricsWriter {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create metrics dir {}", parent.display()))?;
        }
        let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
        Ok(Self {
            tick_writer: BufWriter::new(file),
        })
    }

    pub fn write_tick(&mut self, metric: &TickMetric) -> Result<()> {
        let line = serde_json::to_string(metric).context("serialize tick metric")?;
        self.tick_writer
            .write_all(line.as_bytes())
            .context("write tick metric")?;
        self.tick_writer
            .write_all(b"\n")
            .context("write tick metric newline")?;
        self.tick_writer.flush().context("flush tick metric")?;
        Ok(())
    }

    pub fn write_summary(path: impl AsRef<Path>, summary: &RunSummary) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create summary dir {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(summary).context("serialize summary")?;
        fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}
