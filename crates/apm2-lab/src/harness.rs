use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use apm2_core::crypto::Signer;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::agent::{AgentAction, AgentInvoker, ClaudeCliInvoker, LabAgent};
use crate::closure::{ClosureConfig, ClosureReducer, CompositeView};
use crate::event::{EventKind, WorkType};
use crate::ledger::{Cursor, LabLedger};
use crate::metrics::{AgentTickMetric, MetricsWriter, OpenedWorkMetric, RunSummary, TickMetric};
use crate::prompt::{build_tick_prompt, write_system_prompts};
use crate::scoring::{AgentDomain, evaluate_submission};
use crate::spec::LabSpec;
use crate::verdict::Verdict;
use crate::world::WorkGenerator;

/// Runs a single live experiment using direct Claude CLI invocations.
pub async fn run_experiment(
    spec: LabSpec,
    requested_condition: Option<&str>,
    seed: u64,
) -> Result<RunSummary> {
    run_experiment_with_invokers(spec, requested_condition, seed, |_| {
        Box::<ClaudeCliInvoker>::default()
    })
    .await
}

/// Runs a single experiment using a custom invoker factory (used by tests).
pub async fn run_experiment_with_invokers<F>(
    spec: LabSpec,
    requested_condition: Option<&str>,
    seed: u64,
    mut invoker_factory: F,
) -> Result<RunSummary>
where
    F: FnMut(&str) -> Box<dyn AgentInvoker>,
{
    let (condition_name, condition) = spec.resolve_condition(requested_condition)?;

    let prompt_paths = write_system_prompts(&spec.agents, Path::new("lab"))?;
    let mut ledger = LabLedger::new();
    let mut world = WorkGenerator::new(&spec, condition, seed)?;
    let mut metrics_writer = MetricsWriter::new(&spec.outputs.metrics_path)?;
    let closure = ClosureReducer::new(ClosureConfig {
        tau_compression_gain: spec.formation_policy.tau_compression_gain,
        max_composite_size: spec.formation_policy.max_composite_size,
        require_all_attestations: spec.formation_policy.require_all_attestations,
    });

    let world_signer = Signer::generate();
    let closure_signer = Signer::generate();

    let mut agents = build_agents(
        &spec,
        &prompt_paths.system_prompt_files,
        &mut invoker_factory,
    )?;
    let agent_domains: HashMap<String, String> = agents
        .iter()
        .map(|agent| (agent.id.clone(), agent.domain.clone()))
        .collect();
    let mut cursors: HashMap<String, Cursor> = spec
        .agents
        .keys()
        .cloned()
        .map(|id| (id, Cursor::start()))
        .collect();

    let mut work_open_tick: HashMap<String, u64> = HashMap::new();
    let mut work_final_tick: HashMap<String, u64> = HashMap::new();
    let mut work_type_map: HashMap<String, WorkType> = HashMap::new();
    let mut work_value_map: HashMap<String, f64> = HashMap::new();

    let mut cumulative_score = 0.0;
    let mut previous_token_total = 0u64;

    let mut formation_tick: Option<u64> = None;
    let mut formation_rationale: Option<String> = None;

    let mut audit_rng = StdRng::seed_from_u64(seed ^ 0xA11E_u64);

    for tick in 1..=condition.ticks {
        let mut opened_metrics = Vec::new();
        let mut admitted_this_tick = Vec::new();
        let mut failed_this_tick = Vec::new();
        let mut agent_metrics = Vec::new();

        // 1) World emits one work item per tick.
        let opened = world.next_event();
        if let EventKind::WorkOpened {
            work_id,
            work_type,
            value,
            ..
        } = &opened
        {
            work_open_tick.insert(work_id.clone(), tick);
            work_type_map.insert(work_id.clone(), *work_type);
            work_value_map.insert(work_id.clone(), *value);
            opened_metrics.push(OpenedWorkMetric {
                id: work_id.clone(),
                work_type: *work_type,
                value: *value,
            });
        }
        ledger.append("world", &world_signer, opened)?;

        // 2) Agent turns (alpha then beta, map order).
        for agent in &mut agents {
            let closure_view = closure.evaluate(ledger.events())?;
            let cursor = *cursors.get(&agent.id).unwrap_or(&Cursor::start());
            let ledger_updates = ledger.render_for_prompt(cursor, 120);
            let open_work = open_work_lines(&closure_view, &work_type_map);
            let composite = active_composite_for(&closure_view.active_composites, &agent.id);

            let prompt = build_tick_prompt(
                tick,
                &agent.id,
                agent.budget_remaining_tokens,
                &ledger_updates,
                &open_work,
                composite,
            );

            let action = agent.act(&prompt).await?;
            let validated = validate_action(
                &action,
                &agent.id,
                &agent.domain,
                &closure_view.active_composites,
                &work_type_map,
                &agent_domains,
                &ledger,
            );

            if let Some(event) = validated.event {
                ledger.append(agent.id.clone(), &agent.signer, event)?;
            }

            cursors.insert(agent.id.clone(), ledger.tail_cursor());
            agent_metrics.push(AgentTickMetric {
                id: agent.id.clone(),
                budget: agent.budget_remaining_tokens,
                action: validated.summary,
            });
        }

        // 3) Optional randomized audit challenge for anti-Goodhart pressure.
        if spec.audit_policy.enabled
            && audit_rng.gen_bool(spec.audit_policy.challenge_rate.clamp(0.0, 1.0))
            && let Some(work_id) = sample_submitted_work_id(&ledger)
        {
            let challenge_id = format!("audit-{tick:03}");
            ledger.append(
                "auditor",
                &closure_signer,
                EventKind::AuditChallenge {
                    work_id,
                    challenge_id,
                    prompt: "Provide independent reasoning evidence".to_string(),
                },
            )?;
        }

        // 4) Closure emits authoritative facts.
        let closure_view = closure.evaluate(ledger.events())?;
        for derived in closure_view.derived_events {
            match &derived {
                EventKind::WorkAdmitted { work_id, .. } => {
                    admitted_this_tick.push(work_id.clone());
                    work_final_tick.insert(work_id.clone(), tick);
                    if let Some(value) = work_value_map.get(work_id) {
                        cumulative_score += spec.scoring.value_weight * value;
                    }
                },
                EventKind::WorkRejected { work_id, .. } => {
                    failed_this_tick.push(work_id.clone());
                    work_final_tick.insert(work_id.clone(), tick);
                    cumulative_score -= spec.scoring.failure_penalty;
                },
                EventKind::CompositeAdmitted {
                    composite_id,
                    gain_delta,
                    ..
                } => {
                    if formation_tick.is_none() {
                        formation_tick = Some(tick);
                        formation_rationale = find_formation_rationale(&ledger, composite_id);
                    }
                    // Small positive signal for successful economically-justified formation.
                    cumulative_score += gain_delta * 0.1;
                },
                EventKind::AuditChallenge { .. }
                | EventKind::AuditResult { .. }
                | EventKind::WorkOpened { .. }
                | EventKind::WorkClaimed { .. }
                | EventKind::WorkSubmitted { .. }
                | EventKind::VerifyAttestation { .. }
                | EventKind::FormationIntent { .. }
                | EventKind::FormationAttestation { .. }
                | EventKind::SubTaskDelegated { .. } => {},
            }
            ledger.append("closure", &closure_signer, derived)?;
        }

        // 5) Token-cost component of objective.
        let token_total: u64 = agents.iter().map(|a| a.total_tokens_used).sum();
        let token_delta = token_total.saturating_sub(previous_token_total);
        cumulative_score -= spec.scoring.token_cost * token_delta as f64;
        previous_token_total = token_total;

        let closure_view = closure.evaluate(ledger.events())?;
        metrics_writer.write_tick(&TickMetric {
            tick,
            work_opened: opened_metrics,
            work_admitted: admitted_this_tick,
            work_failed: failed_this_tick,
            agents: agent_metrics,
            formations_pending: closure_view.pending_formations,
            composites_active: closure_view.active_composites.len(),
            cumulative_score,
        })?;
    }

    ledger.dump_jsonl(&spec.outputs.ledger_path)?;

    let (compound_success_rate_pre, compound_success_rate_post) = compound_success_rates(
        &work_type_map,
        &work_open_tick,
        &work_final_tick,
        &ledger,
        formation_tick,
    );

    let total_tokens: u64 = agents.iter().map(|a| a.total_tokens_used).sum();
    let total_cli_calls: u64 = agents.iter().map(|a| a.total_cli_calls).sum();

    let summary = RunSummary {
        seed,
        condition: condition_name.to_string(),
        formation_occurred: formation_tick.is_some(),
        formation_tick,
        formation_rationale,
        compound_success_rate_pre,
        compound_success_rate_post,
        total_score: cumulative_score,
        total_tokens,
        total_cli_calls,
    };

    MetricsWriter::write_summary(&spec.outputs.summary_path, &summary)?;
    Ok(summary)
}

fn build_agents<F>(
    spec: &LabSpec,
    prompt_files: &BTreeMap<String, std::path::PathBuf>,
    invoker_factory: &mut F,
) -> Result<Vec<LabAgent>>
where
    F: FnMut(&str) -> Box<dyn AgentInvoker>,
{
    let mut agents = Vec::new();
    for (agent_id, agent_spec) in &spec.agents {
        let prompt_file = prompt_files
            .get(agent_id)
            .ok_or_else(|| anyhow::anyhow!("missing system prompt file for {agent_id}"))?;

        let agent = LabAgent::new(
            agent_id.clone(),
            agent_spec.domain.clone(),
            Signer::generate(),
            spec.model.clone(),
            prompt_file.clone(),
            spec.budget_per_agent_tokens,
            invoker_factory(agent_id),
        );
        agents.push(agent);
    }
    Ok(agents)
}

struct ValidatedAction {
    event: Option<EventKind>,
    summary: String,
}

fn validate_action(
    action: &AgentAction,
    actor_id: &str,
    actor_domain: &str,
    active_composites: &BTreeMap<String, CompositeView>,
    work_type_map: &HashMap<String, WorkType>,
    agent_domains: &HashMap<String, String>,
    ledger: &LabLedger,
) -> ValidatedAction {
    let event = match action {
        AgentAction::Claim { work_id } => {
            work_type_map.get(work_id).map(|_| EventKind::WorkClaimed {
                work_id: work_id.clone(),
                agent_id: actor_id.to_string(),
            })
        },

        AgentAction::Submit { work_id, solution } => {
            work_type_map
                .get(work_id)
                .map(|_| EventKind::WorkSubmitted {
                    work_id: work_id.clone(),
                    agent_id: actor_id.to_string(),
                    solution: solution.clone(),
                    cost_tokens: (solution.chars().count() as u64 / 4).max(1),
                })
        },

        AgentAction::Verify {
            work_id,
            verdict,
            reasoning,
        } => {
            if let Some(submission) = latest_submission_for_work(ledger, work_id)
                && submission.agent_id != actor_id
            {
                let domain = find_agent_domain(agent_domains, &submission.agent_id);
                let submitter_is_in_composite = active_composites
                    .values()
                    .any(|c| c.members.contains(&submission.agent_id));

                let work_type = work_type_map
                    .get(work_id)
                    .copied()
                    .unwrap_or(WorkType::Analyze);
                let eval = evaluate_submission(
                    work_type,
                    AgentDomain::from_label(domain),
                    &submission.solution,
                    submitter_is_in_composite,
                );

                let provided: Verdict = (*verdict).into();
                let effective = if eval.expected_pass {
                    provided
                } else {
                    Verdict::Fail
                };

                Some(EventKind::VerifyAttestation {
                    work_id: work_id.clone(),
                    verifier_id: actor_id.to_string(),
                    verdict: effective,
                    reasoning: format!(
                        "{reasoning} | eval_score={:.3} | verifier_domain={}",
                        eval.score, actor_domain
                    ),
                })
            } else {
                None
            }
        },

        AgentAction::ProposeFormation {
            partner_ids,
            rationale,
        } => {
            if partner_ids.is_empty() {
                None
            } else {
                let mut members: Vec<String> = partner_ids.clone();
                if !members.iter().any(|id| id == actor_id) {
                    members.push(actor_id.to_string());
                }
                members.sort();
                members.dedup();

                let composite_id = composite_id_for_members(&members);
                Some(EventKind::FormationIntent {
                    composite_id,
                    members,
                    rationale: rationale.clone(),
                })
            }
        },

        AgentAction::AttestFormation {
            composite_id,
            approve,
            rationale,
        } => {
            let has_intent = ledger.events().iter().any(|event| {
                matches!(
                    &event.event,
                    EventKind::FormationIntent {
                        composite_id: id,
                        ..
                    } if id == composite_id
                )
            });
            if has_intent {
                Some(EventKind::FormationAttestation {
                    composite_id: composite_id.clone(),
                    attester_id: actor_id.to_string(),
                    approve: *approve,
                    rationale: rationale.clone(),
                })
            } else {
                None
            }
        },

        AgentAction::Delegate {
            work_id,
            delegate_to,
            sub_task,
        } => {
            let maybe_composite = active_composites.values().find(|comp| {
                comp.members.iter().any(|m| m == actor_id)
                    && comp.members.iter().any(|m| m == delegate_to)
            });
            if work_type_map.contains_key(work_id) {
                maybe_composite.map(|comp| EventKind::SubTaskDelegated {
                    composite_id: comp.composite_id.clone(),
                    work_id: work_id.clone(),
                    delegate_to: delegate_to.clone(),
                    sub_task: sub_task.clone(),
                })
            } else {
                None
            }
        },

        AgentAction::Pass => None,
    };

    ValidatedAction {
        event,
        summary: action.summary(),
    }
}

fn latest_submission_for_work(ledger: &LabLedger, work_id: &str) -> Option<SubmittedView> {
    ledger.events().iter().rev().find_map(|event| {
        if let EventKind::WorkSubmitted {
            work_id: submitted,
            agent_id,
            solution,
            ..
        } = &event.event
            && submitted == work_id
        {
            return Some(SubmittedView {
                agent_id: agent_id.clone(),
                solution: solution.clone(),
            });
        }
        None
    })
}

struct SubmittedView {
    agent_id: String,
    solution: String,
}

fn find_agent_domain<'a>(agent_domains: &'a HashMap<String, String>, agent_id: &str) -> &'a str {
    agent_domains
        .get(agent_id)
        .map(String::as_str)
        .unwrap_or("other")
}

fn open_work_lines(
    closure: &crate::closure::ClosureSnapshot,
    work_type_map: &HashMap<String, WorkType>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for (work_id, view) in &closure.work_status {
        if view.admitted || view.rejected {
            continue;
        }
        if let Some(work_type) = work_type_map.get(work_id).copied().or(view.opened_type) {
            lines.push(format!(
                "{work_id} [{work_type}] verdict={:?}",
                view.verdict
            ));
        }
    }
    lines.sort();
    lines
}

fn active_composite_for<'a>(
    composites: &'a BTreeMap<String, CompositeView>,
    agent_id: &str,
) -> Option<&'a CompositeView> {
    composites
        .values()
        .find(|composite| composite.members.iter().any(|member| member == agent_id))
}

fn composite_id_for_members(members: &[String]) -> String {
    let joined = members.join("|");
    let hash = apm2_core::crypto::EventHasher::hash_content(joined.as_bytes());
    let short = hash
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("");
    format!("cmp-{short}")
}

fn find_formation_rationale(ledger: &LabLedger, composite_id: &str) -> Option<String> {
    ledger.events().iter().rev().find_map(|event| {
        if let EventKind::FormationIntent {
            composite_id: id,
            rationale,
            ..
        } = &event.event
            && id == composite_id
        {
            return Some(rationale.clone());
        }
        None
    })
}

fn sample_submitted_work_id(ledger: &LabLedger) -> Option<String> {
    let mut seen = HashSet::new();
    for event in ledger.events().iter().rev() {
        if let EventKind::WorkSubmitted { work_id, .. } = &event.event
            && seen.insert(work_id.clone())
        {
            return Some(work_id.clone());
        }
    }
    None
}

fn compound_success_rates(
    work_type_map: &HashMap<String, WorkType>,
    _work_open_tick: &HashMap<String, u64>,
    work_final_tick: &HashMap<String, u64>,
    ledger: &LabLedger,
    formation_tick: Option<u64>,
) -> (f64, f64) {
    let mut admitted_ids = HashSet::new();
    let mut rejected_ids = HashSet::new();
    for event in ledger.events() {
        match &event.event {
            EventKind::WorkAdmitted { work_id, .. } => {
                admitted_ids.insert(work_id.clone());
            },
            EventKind::WorkRejected { work_id, .. } => {
                rejected_ids.insert(work_id.clone());
            },
            _ => {},
        }
    }

    let split = formation_tick.unwrap_or(u64::MAX);
    let mut pre_total = 0usize;
    let mut pre_success = 0usize;
    let mut post_total = 0usize;
    let mut post_success = 0usize;

    for (work_id, work_type) in work_type_map {
        if *work_type != WorkType::Compound {
            continue;
        }
        let Some(final_tick) = work_final_tick.get(work_id).copied() else {
            continue;
        };

        let success = admitted_ids.contains(work_id) && !rejected_ids.contains(work_id);
        if final_tick < split {
            pre_total += 1;
            if success {
                pre_success += 1;
            }
        } else {
            post_total += 1;
            if success {
                post_success += 1;
            }
        }
    }

    let pre = if pre_total == 0 {
        0.0
    } else {
        pre_success as f64 / pre_total as f64
    };
    let post = if post_total == 0 {
        0.0
    } else {
        post_success as f64 / post_total as f64
    };

    (pre, post)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::run_experiment_with_invokers;
    use crate::agent::MockInvoker;
    use crate::spec::{
        AgentSpec, AuditPolicy, ConditionSpec, FormationPolicy, LabSpec, OutputSpec, ScoringSpec,
        WorkTypeSpec,
    };

    fn mini_spec(metrics: &str, summary: &str, ledger: &str) -> LabSpec {
        let mut agents = BTreeMap::new();
        agents.insert(
            "alpha".to_string(),
            AgentSpec {
                domain: "analytical".to_string(),
                description: "analysis".to_string(),
            },
        );
        agents.insert(
            "beta".to_string(),
            AgentSpec {
                domain: "creative".to_string(),
                description: "synthesis".to_string(),
            },
        );

        let mut work_types = BTreeMap::new();
        work_types.insert(
            "analyze".to_string(),
            WorkTypeSpec {
                value: 1.0,
                skills: vec!["analytical".to_string()],
                description_template: "Decompose {topic}".to_string(),
            },
        );
        work_types.insert(
            "synthesize".to_string(),
            WorkTypeSpec {
                value: 1.0,
                skills: vec!["creative".to_string()],
                description_template: "Combine {elements}".to_string(),
            },
        );
        work_types.insert(
            "compound".to_string(),
            WorkTypeSpec {
                value: 4.0,
                skills: vec!["analytical".to_string(), "creative".to_string()],
                description_template: "Analyze {topic}, then synthesize into {output}".to_string(),
            },
        );

        let mut conditions = BTreeMap::new();
        conditions.insert(
            "control".to_string(),
            ConditionSpec {
                mix: BTreeMap::from([
                    ("analyze".to_string(), 0.5),
                    ("synthesize".to_string(), 0.5),
                    ("compound".to_string(), 0.0),
                ]),
                ticks: 2,
            },
        );

        LabSpec {
            kind: "apm2.lab.test".to_string(),
            version: "v1".to_string(),
            agents,
            work_types,
            conditions,
            budget_per_agent_tokens: 1_000,
            model: "sonnet".to_string(),
            scoring: ScoringSpec {
                value_weight: 1.0,
                failure_penalty: 2.0,
                token_cost: 0.0,
            },
            outputs: OutputSpec {
                metrics_path: metrics.to_string(),
                summary_path: summary.to_string(),
                ledger_path: ledger.to_string(),
            },
            formation_policy: FormationPolicy::default(),
            audit_policy: AuditPolicy::default(),
        }
    }

    #[tokio::test]
    async fn mock_run_writes_summary() {
        let temp = tempfile::tempdir().expect("tempdir");
        let metrics = temp.path().join("metrics.jsonl");
        let summary = temp.path().join("summary.json");
        let ledger = temp.path().join("ledger.jsonl");
        let spec = mini_spec(
            &metrics.display().to_string(),
            &summary.display().to_string(),
            &ledger.display().to_string(),
        );

        let mut script_map = BTreeMap::new();
        script_map.insert(
            "alpha".to_string(),
            vec![
                "{\"action\":\"pass\"}".to_string(),
                "{\"action\":\"pass\"}".to_string(),
            ],
        );
        script_map.insert(
            "beta".to_string(),
            vec![
                "{\"action\":\"pass\"}".to_string(),
                "{\"action\":\"pass\"}".to_string(),
            ],
        );

        let summary_out = run_experiment_with_invokers(spec, Some("control"), 7, |id| {
            let responses = script_map.get(id).cloned().unwrap_or_default();
            Box::new(MockInvoker::with_scripted(responses))
        })
        .await
        .expect("mock run");

        assert_eq!(summary_out.seed, 7);
        assert!(summary.exists());
        assert!(metrics.exists());
        assert!(ledger.exists());
    }
}
