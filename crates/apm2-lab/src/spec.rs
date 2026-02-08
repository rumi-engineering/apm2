use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::event::WorkType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabSpec {
    pub kind: String,
    pub version: String,
    pub agents: BTreeMap<String, AgentSpec>,
    pub work_types: BTreeMap<String, WorkTypeSpec>,
    pub conditions: BTreeMap<String, ConditionSpec>,
    pub budget_per_agent_tokens: u64,
    pub model: String,
    pub scoring: ScoringSpec,
    pub outputs: OutputSpec,
    #[serde(default)]
    pub formation_policy: FormationPolicy,
    #[serde(default)]
    pub audit_policy: AuditPolicy,
}

impl LabSpec {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).with_context(|| format!("read spec {}", path.display()))?;
        let spec: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse spec {}", path.display()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        if self.agents.len() < 2 {
            return Err(anyhow!("spec requires at least two agents"));
        }
        if self.conditions.is_empty() {
            return Err(anyhow!("spec requires at least one condition"));
        }
        if self.work_types.is_empty() {
            return Err(anyhow!("spec requires at least one work type"));
        }
        for (condition_name, condition) in &self.conditions {
            let sum: f64 = condition.mix.values().sum();
            if (sum - 1.0).abs() > 1e-6 {
                return Err(anyhow!(
                    "condition {condition_name} mix must sum to 1.0 (got {sum})"
                ));
            }
            if condition.ticks == 0 {
                return Err(anyhow!("condition {condition_name} ticks must be > 0"));
            }
        }
        Ok(())
    }

    pub fn resolve_condition<'a>(
        &'a self,
        requested: Option<&str>,
    ) -> Result<(String, &'a ConditionSpec)> {
        if let Some(requested) = requested {
            let condition = self
                .conditions
                .get(requested)
                .ok_or_else(|| anyhow!("unknown condition '{requested}'"))?;
            return Ok((requested.to_string(), condition));
        }

        if let Some(c) = self.conditions.get("treatment") {
            return Ok(("treatment".to_string(), c));
        }

        let first = self
            .conditions
            .iter()
            .next()
            .ok_or_else(|| anyhow!("spec contains no conditions"))?;
        Ok((first.0.clone(), first.1))
    }

    pub fn work_type_from_key(key: &str) -> Result<WorkType> {
        match key {
            "analyze" => Ok(WorkType::Analyze),
            "synthesize" => Ok(WorkType::Synthesize),
            "compound" => Ok(WorkType::Compound),
            other => Err(anyhow!("unknown work type key '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSpec {
    pub domain: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkTypeSpec {
    pub value: f64,
    pub skills: Vec<String>,
    pub description_template: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionSpec {
    pub mix: BTreeMap<String, f64>,
    pub ticks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringSpec {
    pub value_weight: f64,
    pub failure_penalty: f64,
    pub token_cost: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSpec {
    pub metrics_path: String,
    pub summary_path: String,
    pub ledger_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormationPolicy {
    #[serde(default = "default_tau")]
    pub tau_compression_gain: f64,
    #[serde(default = "default_max_composite_size")]
    pub max_composite_size: usize,
    #[serde(default = "default_require_all_attestations")]
    pub require_all_attestations: bool,
}

impl Default for FormationPolicy {
    fn default() -> Self {
        Self {
            tau_compression_gain: default_tau(),
            max_composite_size: default_max_composite_size(),
            require_all_attestations: default_require_all_attestations(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_audit_rate")]
    pub challenge_rate: f64,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            challenge_rate: default_audit_rate(),
        }
    }
}

const fn default_tau() -> f64 {
    0.15
}

const fn default_max_composite_size() -> usize {
    8
}

const fn default_require_all_attestations() -> bool {
    true
}

const fn default_audit_rate() -> f64 {
    0.05
}
