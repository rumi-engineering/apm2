use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::Result;

use crate::event::{EventKind, HolonId, SignedEvent, WorkType};
use crate::verdict::Verdict;

#[derive(Debug, Clone)]
pub struct ClosureConfig {
    pub tau_compression_gain: f64,
    pub max_composite_size: usize,
    pub require_all_attestations: bool,
}

#[derive(Debug, Clone)]
pub struct CompositeView {
    pub composite_id: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WorkStatusView {
    pub opened_type: Option<WorkType>,
    pub admitted: bool,
    pub rejected: bool,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Default)]
pub struct ClosureSnapshot {
    pub derived_events: Vec<EventKind>,
    pub admitted_work_ids: BTreeSet<String>,
    pub rejected_work_ids: BTreeSet<String>,
    pub work_status: BTreeMap<String, WorkStatusView>,
    pub pending_formations: usize,
    pub active_composites: BTreeMap<String, CompositeView>,
}

#[derive(Debug, Clone)]
struct Submission {
    agent_id: String,
}

#[derive(Debug, Clone)]
struct Verification {
    verifier_id: String,
    verdict: Verdict,
}

#[derive(Debug, Clone)]
struct FormationIntent {
    composite_id: String,
    members: Vec<String>,
    rationale: String,
}

/// Pure closure reducer over lab ledger events.
pub struct ClosureReducer {
    config: ClosureConfig,
}

impl ClosureReducer {
    #[must_use]
    pub const fn new(config: ClosureConfig) -> Self {
        Self { config }
    }

    pub fn evaluate(&self, events: &[SignedEvent]) -> Result<ClosureSnapshot> {
        let mut snapshot = ClosureSnapshot::default();

        let mut work_type: HashMap<String, WorkType> = HashMap::new();
        let mut submissions: HashMap<String, Vec<Submission>> = HashMap::new();
        let mut verifications: HashMap<String, Vec<Verification>> = HashMap::new();
        let mut already_admitted: HashSet<String> = HashSet::new();
        let mut already_rejected: HashSet<String> = HashSet::new();

        let mut formation_intents: HashMap<String, FormationIntent> = HashMap::new();
        let mut formation_attestations: HashMap<String, HashMap<HolonId, bool>> = HashMap::new();

        for event in events {
            match &event.event {
                EventKind::WorkOpened {
                    work_id,
                    work_type: wt,
                    ..
                } => {
                    work_type.insert(work_id.clone(), *wt);
                },
                EventKind::WorkSubmitted {
                    work_id,
                    agent_id,
                    solution: _,
                    ..
                } => {
                    submissions
                        .entry(work_id.clone())
                        .or_default()
                        .push(Submission {
                            agent_id: agent_id.clone(),
                        });
                },
                EventKind::VerifyAttestation {
                    work_id,
                    verifier_id,
                    verdict,
                    ..
                } => {
                    verifications
                        .entry(work_id.clone())
                        .or_default()
                        .push(Verification {
                            verifier_id: verifier_id.clone(),
                            verdict: *verdict,
                        });
                },
                EventKind::WorkAdmitted { work_id, .. } => {
                    already_admitted.insert(work_id.clone());
                    snapshot.admitted_work_ids.insert(work_id.clone());
                },
                EventKind::WorkRejected { work_id, .. } => {
                    already_rejected.insert(work_id.clone());
                    snapshot.rejected_work_ids.insert(work_id.clone());
                },
                EventKind::FormationIntent {
                    composite_id,
                    members,
                    rationale,
                } => {
                    formation_intents.insert(
                        composite_id.clone(),
                        FormationIntent {
                            composite_id: composite_id.clone(),
                            members: members.clone(),
                            rationale: rationale.clone(),
                        },
                    );
                },
                EventKind::FormationAttestation {
                    composite_id,
                    attester_id,
                    approve,
                    ..
                } => {
                    formation_attestations
                        .entry(composite_id.clone())
                        .or_default()
                        .insert(attester_id.clone(), *approve);
                },
                EventKind::CompositeAdmitted {
                    composite_id,
                    members,
                    ..
                } => {
                    snapshot.active_composites.insert(
                        composite_id.clone(),
                        CompositeView {
                            composite_id: composite_id.clone(),
                            members: members.clone(),
                        },
                    );
                },
                EventKind::WorkClaimed { .. }
                | EventKind::SubTaskDelegated { .. }
                | EventKind::AuditChallenge { .. }
                | EventKind::AuditResult { .. } => {},
            }
        }

        let mut all_work_ids: BTreeSet<String> = BTreeSet::new();
        all_work_ids.extend(work_type.keys().cloned());
        all_work_ids.extend(submissions.keys().cloned());
        all_work_ids.extend(verifications.keys().cloned());
        all_work_ids.extend(already_admitted.iter().cloned());
        all_work_ids.extend(already_rejected.iter().cloned());

        for work_id in all_work_ids {
            let opened_type = work_type.get(&work_id).copied();
            let latest_submission = submissions
                .get(&work_id)
                .and_then(|items| items.last())
                .cloned();
            let item_verifications = verifications.get(&work_id).cloned().unwrap_or_default();

            let any_fail = item_verifications
                .iter()
                .any(|v| v.verdict == Verdict::Fail);
            let has_independent_pass = latest_submission.as_ref().is_some_and(|submission| {
                item_verifications
                    .iter()
                    .any(|v| v.verdict == Verdict::Pass && v.verifier_id != submission.agent_id)
            });

            let verdict = if any_fail {
                Verdict::Fail
            } else if has_independent_pass {
                Verdict::Pass
            } else {
                Verdict::Pending
            };

            let admitted = already_admitted.contains(&work_id);
            let rejected = already_rejected.contains(&work_id);
            snapshot.work_status.insert(
                work_id.clone(),
                WorkStatusView {
                    opened_type,
                    admitted,
                    rejected,
                    verdict,
                },
            );

            if !admitted && !rejected {
                match verdict {
                    Verdict::Pass => {
                        let receipt_hash = SignedEvent::receipt_hash(&EventKind::WorkAdmitted {
                            work_id: work_id.clone(),
                            receipt_hash: [0u8; 32],
                        })?;
                        snapshot.admitted_work_ids.insert(work_id.clone());
                        snapshot.derived_events.push(EventKind::WorkAdmitted {
                            work_id,
                            receipt_hash,
                        });
                    },
                    Verdict::Fail => {
                        let receipt_hash = SignedEvent::receipt_hash(&EventKind::WorkRejected {
                            work_id: work_id.clone(),
                            reason: "authoritative fail attestation".to_string(),
                            receipt_hash: [0u8; 32],
                        })?;
                        snapshot.rejected_work_ids.insert(work_id.clone());
                        snapshot.derived_events.push(EventKind::WorkRejected {
                            work_id,
                            reason: "authoritative fail attestation".to_string(),
                            receipt_hash,
                        });
                    },
                    Verdict::Pending => {},
                }
            }
        }

        // Formation closure.
        for intent in formation_intents.into_values() {
            if snapshot
                .active_composites
                .contains_key(&intent.composite_id)
            {
                continue;
            }
            let dedup_members: BTreeSet<_> = intent.members.iter().cloned().collect();
            if dedup_members.len() != intent.members.len() {
                snapshot.pending_formations += 1;
                continue;
            }
            if intent.members.is_empty() || intent.members.len() > self.config.max_composite_size {
                snapshot.pending_formations += 1;
                continue;
            }

            let attestations = formation_attestations
                .get(&intent.composite_id)
                .cloned()
                .unwrap_or_default();
            let any_deny = attestations
                .iter()
                .any(|(member, approve)| dedup_members.contains(member) && !approve);
            if any_deny {
                snapshot.pending_formations += 1;
                continue;
            }

            let approvals = intent
                .members
                .iter()
                .filter(|m| attestations.get(*m) == Some(&true))
                .count();
            let quorum_met = if self.config.require_all_attestations {
                approvals == intent.members.len()
            } else {
                approvals * 2 >= intent.members.len()
            };
            if !quorum_met {
                snapshot.pending_formations += 1;
                continue;
            }

            // I(S) - B(S) - F(S) > tau(risk), operationalized with local, replayable
            // proxies.
            let delta = formation_gain_delta(
                &intent,
                &submissions,
                &verifications,
                &work_type,
                self.config.max_composite_size,
            );
            if delta < self.config.tau_compression_gain {
                snapshot.pending_formations += 1;
                continue;
            }

            let receipt_hash = SignedEvent::receipt_hash(&EventKind::CompositeAdmitted {
                composite_id: intent.composite_id.clone(),
                members: intent.members.clone(),
                receipt_hash: [0u8; 32],
                gain_delta: delta,
            })?;

            let view = CompositeView {
                composite_id: intent.composite_id.clone(),
                members: intent.members.clone(),
            };
            snapshot
                .active_composites
                .insert(intent.composite_id.clone(), view);
            snapshot.derived_events.push(EventKind::CompositeAdmitted {
                composite_id: intent.composite_id,
                members: intent.members,
                receipt_hash,
                gain_delta: delta,
            });
        }

        Ok(snapshot)
    }
}

fn formation_gain_delta(
    intent: &FormationIntent,
    submissions: &HashMap<String, Vec<Submission>>,
    verifications: &HashMap<String, Vec<Verification>>,
    work_type: &HashMap<String, WorkType>,
    max_composite_size: usize,
) -> f64 {
    let member_set: HashSet<_> = intent.members.iter().cloned().collect();

    let mut compound_attempts = 0usize;
    let mut compound_fail_votes = 0usize;
    let mut compound_verifications = 0usize;
    let mut rationale_bonus = 0.0;

    let rationale_lower = intent.rationale.to_ascii_lowercase();
    if rationale_lower.contains("compound") || rationale_lower.contains("delegate") {
        rationale_bonus += 0.05;
    }
    if rationale_lower.contains("budget") || rationale_lower.contains("cost") {
        rationale_bonus += 0.05;
    }

    for (work_id, subs) in submissions {
        if work_type.get(work_id) != Some(&WorkType::Compound) {
            continue;
        }
        if subs.iter().any(|s| member_set.contains(&s.agent_id)) {
            compound_attempts += 1;
        }
    }

    for (work_id, vs) in verifications {
        if work_type.get(work_id) != Some(&WorkType::Compound) {
            continue;
        }
        for v in vs {
            if member_set.contains(&v.verifier_id) {
                compound_verifications += 1;
                if v.verdict == Verdict::Fail {
                    compound_fail_votes += 1;
                }
            }
        }
    }

    let i_cost = 0.8 * compound_attempts as f64
        + 1.3 * compound_fail_votes as f64
        + 0.2 * compound_verifications as f64;
    let b_cost = 0.9 + 0.15 * intent.members.len() as f64;
    let f_cost = 0.55 + 0.1 * (intent.members.len().saturating_sub(1)) as f64;
    let risk_penalty = (intent.members.len() as f64 / max_composite_size as f64) * 0.15;

    (i_cost - b_cost - f_cost - risk_penalty + rationale_bonus).max(0.0)
}

#[cfg(test)]
mod tests {
    use apm2_core::crypto::Signer;

    use super::{ClosureConfig, ClosureReducer};
    use crate::event::{EventKind, SignedEvent, WorkType};
    use crate::ledger::LabLedger;
    use crate::verdict::Verdict;

    fn cfg() -> ClosureConfig {
        ClosureConfig {
            tau_compression_gain: 0.15,
            max_composite_size: 8,
            require_all_attestations: true,
        }
    }

    #[test]
    fn deterministic_and_idempotent() {
        let signer = Signer::generate();
        let mut ledger = LabLedger::new();
        ledger
            .append(
                "world",
                &signer,
                EventKind::WorkOpened {
                    work_id: "w-001".to_string(),
                    work_type: WorkType::Analyze,
                    value: 1.0,
                    description: "desc".to_string(),
                },
            )
            .expect("open");
        ledger
            .append(
                "alpha",
                &signer,
                EventKind::WorkSubmitted {
                    work_id: "w-001".to_string(),
                    agent_id: "alpha".to_string(),
                    solution: "1. step one 2. step two".to_string(),
                    cost_tokens: 10,
                },
            )
            .expect("submit");
        ledger
            .append(
                "beta",
                &signer,
                EventKind::VerifyAttestation {
                    work_id: "w-001".to_string(),
                    verifier_id: "beta".to_string(),
                    verdict: Verdict::Pass,
                    reasoning: "ok".to_string(),
                },
            )
            .expect("verify");

        let reducer = ClosureReducer::new(cfg());
        let a = reducer.evaluate(ledger.events()).expect("evaluate a");
        let b = reducer.evaluate(ledger.events()).expect("evaluate b");

        assert_eq!(a.derived_events.len(), b.derived_events.len());
        assert_eq!(a.admitted_work_ids, b.admitted_work_ids);
    }

    #[test]
    fn fail_dominates_even_with_pass_present() {
        let signer = Signer::generate();
        let mut events = Vec::new();

        let mut prev = [0u8; 32];
        for (seq, kind) in [
            EventKind::WorkOpened {
                work_id: "w-1".to_string(),
                work_type: WorkType::Analyze,
                value: 1.0,
                description: "x".to_string(),
            },
            EventKind::WorkSubmitted {
                work_id: "w-1".to_string(),
                agent_id: "alpha".to_string(),
                solution: "analysis".to_string(),
                cost_tokens: 10,
            },
            EventKind::VerifyAttestation {
                work_id: "w-1".to_string(),
                verifier_id: "beta".to_string(),
                verdict: Verdict::Pass,
                reasoning: "ok".to_string(),
            },
            EventKind::VerifyAttestation {
                work_id: "w-1".to_string(),
                verifier_id: "beta".to_string(),
                verdict: Verdict::Fail,
                reasoning: "fail".to_string(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let signed =
                SignedEvent::new((seq + 1) as u64, "actor", &signer, prev, kind, 1).expect("sign");
            prev = signed.event_hash;
            events.push(signed);
        }

        let reducer = ClosureReducer::new(cfg());
        let snap = reducer.evaluate(&events).expect("evaluate");
        assert!(snap.rejected_work_ids.contains("w-1"));
        assert!(!snap.admitted_work_ids.contains("w-1"));
    }
}
