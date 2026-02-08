use crate::event::WorkType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentDomain {
    Analytical,
    Creative,
    Other,
}

impl AgentDomain {
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        match label.to_ascii_lowercase().as_str() {
            "analytical" => Self::Analytical,
            "creative" => Self::Creative,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QualityEval {
    pub score: f64,
    pub expected_pass: bool,
}

#[must_use]
pub fn evaluate_submission(
    work_type: WorkType,
    domain: AgentDomain,
    solution: &str,
    composite_member: bool,
) -> QualityEval {
    let words = solution.split_whitespace().count() as f64;
    let effort_factor = (words / 80.0).clamp(0.15, 1.0);

    let lower = solution.to_ascii_lowercase();
    let addresses_problem = contains_any(
        &lower,
        &["plan", "steps", "analysis", "synthesis", "approach"],
    );

    let structure_bonus = if contains_any(&lower, &["1.", "2.", "3.", "- "]) {
        0.10
    } else {
        0.0
    };

    let domain_match = match (work_type, domain) {
        (WorkType::Analyze, AgentDomain::Analytical) => 0.85,
        (WorkType::Analyze, AgentDomain::Creative) => 0.40,
        (WorkType::Synthesize, AgentDomain::Creative) => 0.85,
        (WorkType::Synthesize, AgentDomain::Analytical) => 0.40,
        (WorkType::Compound, AgentDomain::Analytical | AgentDomain::Creative) => {
            if composite_member || contains_any(&lower, &["analyze", "synthesize"]) {
                0.75
            } else {
                0.35
            }
        },
        (_, AgentDomain::Other) => 0.35,
    };

    let problem_bonus = if addresses_problem { 0.10 } else { -0.15 };
    let score = (domain_match * effort_factor + structure_bonus + problem_bonus).clamp(0.0, 1.0);

    let threshold = match work_type {
        WorkType::Compound => 0.62,
        WorkType::Analyze | WorkType::Synthesize => 0.55,
    };

    QualityEval {
        score,
        expected_pass: score >= threshold,
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}
