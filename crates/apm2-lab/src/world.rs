use rand::distributions::{Distribution, WeightedIndex};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::event::{EventKind, WorkType};
use crate::spec::{ConditionSpec, LabSpec, WorkTypeSpec};

#[derive(Debug)]
pub struct WorkGenerator {
    rng: StdRng,
    weighted: WeightedIndex<f64>,
    work_types: Vec<WorkType>,
    analyze: WorkTypeSpec,
    synthesize: WorkTypeSpec,
    compound: WorkTypeSpec,
    next_index: u64,
}

impl WorkGenerator {
    pub fn new(spec: &LabSpec, condition: &ConditionSpec, seed: u64) -> anyhow::Result<Self> {
        let analyze = spec
            .work_types
            .get("analyze")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing work_types.analyze in spec"))?;
        let synthesize = spec
            .work_types
            .get("synthesize")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing work_types.synthesize in spec"))?;
        let compound = spec
            .work_types
            .get("compound")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing work_types.compound in spec"))?;

        let mut work_types = Vec::new();
        let mut weights = Vec::new();
        for (k, weight) in &condition.mix {
            let wt = LabSpec::work_type_from_key(k)?;
            work_types.push(wt);
            weights.push(*weight);
        }

        let weighted = WeightedIndex::new(weights)?;

        Ok(Self {
            rng: StdRng::seed_from_u64(seed),
            weighted,
            work_types,
            analyze,
            synthesize,
            compound,
            next_index: 1,
        })
    }

    #[must_use]
    pub fn next_event(&mut self) -> EventKind {
        let idx = self.weighted.sample(&mut self.rng);
        let work_type = self.work_types[idx];
        let work_id = format!("w-{:03}", self.next_index);
        self.next_index += 1;

        let (value, description) = match work_type {
            WorkType::Analyze => (
                self.analyze.value,
                fill_template(&self.analyze.description_template, &mut self.rng),
            ),
            WorkType::Synthesize => (
                self.synthesize.value,
                fill_template(&self.synthesize.description_template, &mut self.rng),
            ),
            WorkType::Compound => (
                self.compound.value,
                fill_template(&self.compound.description_template, &mut self.rng),
            ),
        };

        EventKind::WorkOpened {
            work_id,
            work_type,
            value,
            description,
        }
    }
}

fn fill_template(template: &str, rng: &mut StdRng) -> String {
    let topics = [
        "module graph",
        "fault domain",
        "caching strategy",
        "deployment pipeline",
        "state machine",
        "type boundary",
    ];
    let elements = [
        "tests, telemetry, and rollback hooks",
        "state, evidence, and policy signals",
        "error budgets, retries, and invariants",
        "interfaces, traits, and adapters",
        "requirements, constraints, and proofs",
    ];
    let outputs = [
        "an executable migration plan",
        "a verifiable architecture memo",
        "a phased rollout strategy",
        "a deterministic acceptance checklist",
    ];

    let mut description = template.to_string();
    let topic = topics[rng.gen_range(0..topics.len())];
    let element = elements[rng.gen_range(0..elements.len())];
    let output = outputs[rng.gen_range(0..outputs.len())];

    description = description.replace("{topic}", topic);
    description = description.replace("{elements}", element);
    description = description.replace("{output}", output);
    description
}
