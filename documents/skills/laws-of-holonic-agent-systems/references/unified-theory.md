{
  "kind": "holonic.unified_theory",
  "meta": {
    "classification": "INTERNAL",
    "created_at": "2026-01-27T02:14:09Z",
    "dependencies": [
      "apm2://skills/laws-of-holonic-agent-systems/references/agent-native-software",
      "apm2://skills/glossary",
      "apm2://skills/laws-of-holonic-agent-systems/references/holonic-agent-network",
      "apm2://skills/laws-of-holonic-agent-systems/references/holonic-agent-system-defects",
      "apm2://skills/laws-of-holonic-agent-systems"
    ],
    "labels": [
      "agent-native",
      "control-loops",
      "evidence",
      "holonic",
      "laws",
      "ledger",
      "security",
      "theory"
    ],
    "provenance": {
      "actor_id": "HOLON-KERNEL-GOVERNANCE",
      "notes": [
        "Grand unified theory for APM2 agent-native holonic SDLC.",
        "Designed for high information compression: structured claims + explicit mappings to laws, mechanisms, and metrics.",
        "All statements are intended to be operationalizable as contracts, gates, reducers, and defect counterexamples."
      ],
      "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001"
    },
    "stable_id": "dcp://apm2.local/governance/holonic_unified_theory@v1",
    "integrity": {
      "attestation_ref": null,
      "attestation_required_for_enforcement": true,
      "attestation_kind": "ed25519"
    }
  },
  "payload": {
    "doc": {
      "id": "APM2-HOLONIC-UNIFIED-THEORY-0001",
      "title": "Grand Unified Theory of Agent-Native Holonic Software (APM2)",
      "status": "draft",
      "effective_date": "2026-01-27",
      "audience": [
        "adapter",
        "agents",
        "cli",
        "context-compiler",
        "daemon",
        "kernel",
        "policy",
        "security",
        "tooling"
      ],
      "scope_tags": [
        "capability-security",
        "content-addressed-storage",
        "context-as-code",
        "event-sourcing",
        "holarchy",
        "recurrence-reduction",
        "verification-economics"
      ]
    },
    "enforcement_model": {
      "node_class": "NORMATIVE",
      "node_classification": {
        "node_class": "NORMATIVE",
        "enum": [
          "NORMATIVE",
          "EXPLANATORY",
          "BACKGROUND"
        ],
        "enforcement_referenceable_classes": [
          "NORMATIVE"
        ],
        "enforcement_ignored_classes": [
          "EXPLANATORY",
          "BACKGROUND"
        ],
        "renderable_classes": [
          "NORMATIVE",
          "EXPLANATORY",
          "BACKGROUND"
        ]
      },
      "rules": {
        "ENF-CLASS-01": {
          "node_class": "NORMATIVE",
          "statement": "Only nodes with node_class=NORMATIVE may be referenced by gates/policies/linters. Nodes with node_class in {EXPLANATORY,BACKGROUND} are non-authoritative and MUST be ignored by enforcement.",
          "violation_class": "POLICY_VIOLATION"
        },
        "ENF-ADMISSION-01": {
          "node_class": "NORMATIVE",
          "statement": "Enforcement MUST require a valid attestation for this document before importing NORMATIVE nodes. If meta.integrity.attestation_ref is missing or unverifiable, enforcement MUST fail-closed and treat this artifact as EXPLANATORY-only.",
          "violation_class": "MEASUREMENT_INTEGRITY",
          "law_refs": [
            "LAW-15"
          ]
        },
        "ENF-COLLECTIONS-01": {
          "node_class": "NORMATIVE",
          "statement": "Collections intended as sets MUST be encoded as maps keyed by stable IDs. If an array-of-objects is used for a set, it MUST be canonically sorted by id; out-of-order arrays are a schema violation.",
          "violation_class": "SCHEMA_VIOLATION",
          "law_refs": [
            "LAW-03",
            "LAW-13"
          ]
        },
        "ENF-ORACLE-01": {
          "node_class": "NORMATIVE",
          "statement": "Open design questions (Q-*) MUST remain EXPLANATORY until resolved by an OracleRequest/Adjudication with receipt-backed evidence. Any resulting enforceable rule must be recorded as a new NORMATIVE node that references the adjudication resolution and evidence.",
          "violation_class": "GOVERNANCE",
          "law_refs": [
            "LAW-01",
            "LAW-15"
          ]
        },
        "ENF-VERIFY-01": {
          "node_class": "NORMATIVE",
          "statement": "Verification MUST satisfy the satisfiability predicate: Valid(Output, Receipt, Evidence) := VerifyReceipt(receipt) ∧ EvidenceSatisfies(contract, evidence) ∧ DigestBindingsHold(output, evidence).",
          "violation_class": "MEASUREMENT_INTEGRITY",
          "law_refs": [
            "LAW-01",
            "LAW-15"
          ]
        },
        "ENF-OCAP-01": {
          "node_class": "NORMATIVE",
          "statement": "Capabilities MUST NOT be discovered; they only enter a holon via explicit delegation events/receipts (PermeabilityReceipt).",
          "violation_class": "POLICY_VIOLATION",
          "law_refs": [
            "LAW-05"
          ]
        }
      },
      "canonicalization": {
        "node_class": "NORMATIVE",
        "json_canonical_form": "JCS",
        "notes": [
          "JSON objects are hashed/signed only after canonicalization (e.g., JCS).",
          "Protobuf signed messages forbid maps; map-like structures must compile to repeated fields sorted before signing."
        ],
        "set_encoding": {
          "preferred": "map",
          "fallback_array_rule": "sorted_by_id_lex"
        }
      }
    },
    "thesis": {
      "one_line": "APM2 is a closed-loop, verifiable control system that compiles intent into authoritative facts under bounded cognition, bounded authority, and non-stationary environments, and it improves itself by converting counterexamples into stronger contracts, gates, and primitives.",
      "core_claims": {
        "THESIS-01": {
          "statement": "Agent-native software engineering is control engineering: sense -> plan -> act -> verify -> commit, repeated under leases, budgets, and stop conditions.",
          "implications": [
            "Tool calls are sensors/actuators in a partially observable control loop; they are not incidental.",
            "Unverified actuation is open-loop and causes state divergence; promotion requires gates and receipts.",
            "Governance is not bureaucracy; it is a controller tuned for stability under measurement and actuation limits."
          ],
          "law_refs": [
            "LAW-01",
            "LAW-12",
            "LAW-14",
            "LAW-15"
          ],
          "node_class": "EXPLANATORY"
        },
        "THESIS-02": {
          "statement": "Truth in the factory is a monotone substrate (append-only ledger + content-addressed evidence); mutable state (workspace, codebase) is a projection derived by reducers.",
          "implications": [
            "Correctness and auditability must not depend on external platforms (forge, consoles); they are projections/adapters.",
            "Recovery and replay are achieved by replaying facts through pure reducers; process memory is disposable (crash-only).",
            "Merge semantics and compaction are part of the truth model, not an implementation detail."
          ],
          "law_refs": [
            "LAW-03",
            "LAW-10",
            "LAW-11",
            "LAW-15"
          ],
          "node_class": "EXPLANATORY"
        },
        "THESIS-03": {
          "statement": "The system must improve by converting evidence-backed counterexamples (defects/findings) into strengthened verifiers, refined context compilation, and stable primitives that reduce recurrence and waste.",
          "implications": [
            "A CI failure is always a defect (even if the code is correct) because it is a counterexample to determinism/clarity and consumes avoidable work.",
            "ZTI (Zero-Tool Ideal) is a directional design goal: scoped implementation should be actuation, not exploration; pack misses are context defects.",
            "Countermeasures repair the factory (guardrails), not just the product."
          ],
          "law_refs": [
            "LAW-02",
            "LAW-06",
            "LAW-08",
            "LAW-14"
          ],
          "node_class": "EXPLANATORY"
        }
      },
      "separation_principles": {
        "SEP-01": {
          "name": "Spec vs State",
          "statement": "Specification content (what should be done) is distinct from workflow state (what has happened). State is derived from facts; spec is referenced by digest (Plan-of-Record).",
          "primary_objects": [
            "Plan",
            "Plan-of-Record",
            "SpecSnapshot"
          ],
          "law_refs": [
            "LAW-03",
            "LAW-07",
            "LAW-13"
          ],
          "node_class": "EXPLANATORY"
        },
        "SEP-02": {
          "name": "Claim vs Evidence",
          "statement": "Claims (summaries, approvals, narratives) are non-authoritative until bound to verifiable evidence and receipts; summaries are receipts with pointers to atomic facts.",
          "primary_objects": [
            "EvidenceBundle",
            "GateReceipt",
            "SummaryReceipt"
          ],
          "law_refs": [
            "LAW-04",
            "LAW-07",
            "LAW-15"
          ],
          "node_class": "EXPLANATORY"
        },
        "SEP-03": {
          "name": "Authority vs Convenience",
          "statement": "External platforms and tools may be used as convenience projections; correctness and auditability must not depend on them.",
          "primary_objects": [
            "Adapter",
            "MergeReceipt",
            "LedgerEvent"
          ],
          "law_refs": [
            "LAW-03",
            "LAW-05",
            "LAW-15"
          ],
          "node_class": "EXPLANATORY"
        }
      }
    },
    "symbols": {
      "notes": [
        "ASCII-only symbols for stable hashing and tool compatibility.",
        "Mathematical statements are operational: each should map to a contract, verifier, receipt, or reducer."
      ],
      "variables": {
        "SYM-W": {
          "name": "W",
          "type": "int",
          "meaning": "Context window capacity (tokens).",
          "node_class": "EXPLANATORY"
        },
        "SYM-p_theta": {
          "name": "p_theta(y|x)",
          "type": "distribution",
          "meaning": "LLM as stochastic conditional transducer over outputs y given context x.",
          "node_class": "EXPLANATORY"
        },
        "SYM-s": {
          "name": "s",
          "type": "representation",
          "meaning": "Injected sufficient-statistics approximation of full history/state used for decision-making.",
          "node_class": "EXPLANATORY"
        },
        "SYM-I": {
          "name": "I(s;a_star)",
          "type": "real",
          "meaning": "Mutual information between representation s and correct action a_star.",
          "node_class": "EXPLANATORY"
        },
        "SYM-S_t": {
          "name": "S_t",
          "type": "state",
          "meaning": "Hidden environment state at time t.",
          "node_class": "EXPLANATORY"
        },
        "SYM-O_t": {
          "name": "O_t",
          "type": "observation",
          "meaning": "Observation at time t (tool outputs, logs, repo state, ledger reads).",
          "node_class": "EXPLANATORY"
        },
        "SYM-A_t": {
          "name": "A_t",
          "type": "action",
          "meaning": "Action at time t (tool invocation, edit, proposal, gate execution).",
          "node_class": "EXPLANATORY"
        },
        "SYM-T": {
          "name": "T(S_t, A_t)",
          "type": "transition",
          "meaning": "Environment transition function; constrained by sandboxing and capability policy.",
          "node_class": "EXPLANATORY"
        },
        "SYM-b_t": {
          "name": "b_t",
          "type": "belief_state",
          "meaning": "Belief state approximation over S_t given observations O_<=t.",
          "node_class": "EXPLANATORY"
        },
        "SYM-P": {
          "name": "P(x)",
          "type": "predicate",
          "meaning": "Contract predicate over artifacts/states; correctness = satisfy P or emit structured failure evidence under bounds.",
          "node_class": "EXPLANATORY"
        },
        "SYM-C_total": {
          "name": "C_total",
          "type": "real",
          "meaning": "Total expected cost objective (tokens + tools + latency + error + security risk).",
          "node_class": "EXPLANATORY"
        }
      },
      "equations": {
        "EQ-01": {
          "expr": "LLM: y ~ p_theta(y|x)",
          "purpose": "Model stochastic cognition; output is a proposal, not proof.",
          "node_class": "EXPLANATORY"
        },
        "EQ-02": {
          "expr": "Context budget: |s| <= W",
          "purpose": "Finite context as a hard capacity constraint.",
          "node_class": "EXPLANATORY"
        },
        "EQ-03": {
          "expr": "Information bottleneck objective: maximize I(s; a_star) subject to |s| <= W",
          "purpose": "Justifies structured context packs and verifiable indices.",
          "node_class": "EXPLANATORY"
        },
        "EQ-04": {
          "expr": "POMDP framing: S_t hidden, O_t observed, A_t chosen, S_{t+1} ~ T(S_t, A_t), agent maintains b_t approx p(S_t|O_<=t)",
          "purpose": "Tool calls as sensing/actuation; stability requires closed-loop verification.",
          "node_class": "EXPLANATORY"
        },
        "EQ-05": {
          "expr": "Event-sourced state: State_t = Reduce(State_0, Events_0..t)",
          "purpose": "Projection theorem; durable truth is events, not mutable state.",
          "node_class": "EXPLANATORY"
        },
        "EQ-06": {
          "expr": "Stability binding: Stability = Contract + Receipt + Evidence",
          "purpose": "Authoritative promotion requires mechanical verification artifacts.",
          "node_class": "EXPLANATORY"
        },
        "EQ-07": {
          "expr": "Objective: minimize E[C_total] = E[C_T + C_U + C_L + C_E + C_S] subject to invariants",
          "purpose": "Verifier economics and risk-weighted gating as optimization under constraints.",
          "node_class": "EXPLANATORY"
        }
      },
      "cost_terms": {
        "C_T": {
          "name": "token_cost",
          "meaning": "Prompt + output token volume.",
          "node_class": "EXPLANATORY"
        },
        "C_U": {
          "name": "tool_cost",
          "meaning": "Tool runtime and external resource usage.",
          "node_class": "EXPLANATORY"
        },
        "C_L": {
          "name": "latency_cost",
          "meaning": "Time-to-result, queueing delays, coordination overhead.",
          "node_class": "EXPLANATORY"
        },
        "C_E": {
          "name": "error_cost",
          "meaning": "Rework, escaped defects, rollback costs.",
          "node_class": "EXPLANATORY"
        },
        "C_S": {
          "name": "security_risk_cost",
          "meaning": "Exposure, capability misuse, information hazards.",
          "node_class": "EXPLANATORY"
        }
      },
      "node_class": "EXPLANATORY"
    },
    "fundamental_constraints": {
      "PHY-01": {
        "name": "Bounded context (finite W) and MDL as a hard budget",
        "statement": "If the minimal description length of correct behavior exceeds W, any injected context is necessarily lossy; ambiguity increases error probability.",
        "failure_modes": [
          "hallucinated_linkage (agent infers relationships not supported by injected facts)",
          "omission_error (relevant state not injected)",
          "staleness_error (injected state outdated)"
        ],
        "control_objectives": [
          "minimize defect_escape_rate correlated with missing context",
          "minimize pack_miss_rate",
          "minimize stuck_proxies (rollbacks, task resets) correlated with context poverty",
          "minimize unplanned_context_discovery_tool_calls (ZTI gap)"
        ],
        "mechanisms": [
          "MECH-CONTEXT-COMPILATION",
          "MECH-CONTEXTPACK",
          "MECH-MDL-BUDGET-REFRACTOR"
        ],
        "law_refs": [
          "LAW-02",
          "LAW-06",
          "LAW-07"
        ],
        "node_class": "BACKGROUND"
      },
      "PHY-02": {
        "name": "Stochastic cognition: proposals require external verification",
        "statement": "LLM outputs are samples from p_theta(y|x); even at temperature 0, decoding is not logical entailment. Authority cannot be granted to claims without verification artifacts.",
        "derived_rules": [
          "bind promotion to signed receipts + raw evidence artifacts",
          "treat flakiness as first-class defects that puncture the determinism envelope",
          "treat summaries as claims until pointer validation succeeds"
        ],
        "mechanisms": [
          "MECH-DETERMINISM-ENVELOPE",
          "MECH-EVIDENCE-BUNDLE",
          "MECH-GATES",
          "MECH-RECEIPTS"
        ],
        "law_refs": [
          "LAW-01",
          "LAW-04",
          "LAW-07",
          "LAW-15"
        ],
        "node_class": "BACKGROUND"
      },
      "PHY-03": {
        "name": "Non-stationarity: temporal pinning and freshness are mandatory",
        "statement": "Dependencies, tools, policies, and model behavior drift; stability requires pinning a 'frozen world' for an episode and making freshness an explicit policy.",
        "derived_rules": [
          "define expiration and drift thresholds by artifact kind and risk tier",
          "reason against content-addressed snapshots (repo, locks, policies) per episode",
          "represent and manage drift deltas explicitly when reconciling frozen truth with current reality"
        ],
        "mechanisms": [
          "MECH-FRESHNESS-POLICY",
          "MECH-SOURCE-SNAPSHOT"
        ],
        "law_refs": [
          "LAW-09",
          "LAW-14"
        ],
        "node_class": "BACKGROUND"
      },
      "PHY-04": {
        "name": "Distributed failure: retries, duplication, partitions are normal",
        "statement": "At-least-once delivery and partial failures are default; actuation must be safe under retries and convergence must be explicit under drift.",
        "derived_rules": [
          "every side effect is idempotent or has explicit compensation/rollback",
          "every tool actuation emits an execution receipt bound to a dedupe key",
          "facts declare merge operators or conflict rule class; conflicts are recorded as defects",
          "reserve consensus for small control planes; prefer convergent replication for data planes"
        ],
        "mechanisms": [
          "MECH-ANTI-ENTROPY",
          "MECH-CONFLICT-RECORDING",
          "MECH-IDEMPOTENT-ACTUATION",
          "MECH-MERGE-ALGEBRA"
        ],
        "law_refs": [
          "LAW-03",
          "LAW-10",
          "LAW-11",
          "LAW-15"
        ],
        "node_class": "BACKGROUND"
      },
      "PHY-05": {
        "name": "Adversarial representation: security is an information+capability problem",
        "statement": "Adversaries target the bounded context channel (prompt injection, poisoned logs, malicious diffs). Safe operation requires dual-axis containment: authority confinement + audit/identity, including context-read firewalls.",
        "derived_rules": [
          "attestation reduces transitive trust: downstream holons accept artifacts via evidence, not narrative",
          "default-deny tool capabilities; no ambient authority",
          "deny-by-default context reads outside ContextPacks; treat escalations as defects unless authorized",
          "prevent confused-deputy: avoid giving an agent knowledge that enables unauthorized actuation"
        ],
        "mechanisms": [
          "MECH-ATTESTATION",
          "MECH-AUDIT-IDENTITY",
          "MECH-LEASES-BUDGETS",
          "MECH-OCAP",
          "MECH-POLICY"
        ],
        "law_refs": [
          "LAW-05",
          "LAW-08",
          "LAW-15"
        ],
        "node_class": "BACKGROUND"
      },
      "PHY-06": {
        "name": "Computability limits: autonomy cannot be absolute",
        "statement": "The halting problem and Rice's theorem imply you cannot generally decide termination, safety, or semantic correctness; practical autonomy must be bounded, constructive, and verifiable.",
        "derived_rules": [
          "correctness = satisfy predicate P(y) OR return structured failure evidence under bound B",
          "critical actions use restricted languages/schemas and canonicalization to reduce ambiguity",
          "explicit adjudication points exist for irreducibly human/multi-stakeholder decisions"
        ],
        "mechanisms": [
          "MECH-LEASES-BUDGETS",
          "MECH-ORACLE-REQUEST",
          "MECH-SEMANTIC-TYPING",
          "MECH-STOP-CONDITIONS"
        ],
        "law_refs": [
          "LAW-12",
          "LAW-13",
          "LAW-14"
        ],
        "node_class": "BACKGROUND"
      },
      "PHY-07": {
        "name": "Search/branching explosion: degrees of freedom must be reduced",
        "statement": "Planning is search; naive branching explodes. The architecture must reduce branching via capabilities, schemas, decomposition, and stable indices so heuristic cognition operates in a tractable space.",
        "derived_rules": [
          "constrain output spaces via schemas and canonical formats",
          "externalize stable indices/manifests to avoid rediscovery",
          "factor tasks into compositional subgoals with explicit dependencies",
          "restrict allowed actions via capabilities and policy"
        ],
        "mechanisms": [
          "MECH-INDEX-LAYERS",
          "MECH-OCAP",
          "MECH-SCHEMAS",
          "MECH-WORK-DECOMPOSITION"
        ],
        "law_refs": [
          "LAW-06",
          "LAW-12",
          "LAW-13"
        ],
        "node_class": "BACKGROUND"
      }
    },
    "truth_topology": {
      "axioms": {
        "TRUTH-AX-01": {
          "statement": "Truth is not a snapshot; truth is an append-only, hash-chained DAG of events with content-addressed evidence pointers.",
          "node_class": "NORMATIVE"
        },
        "TRUTH-AX-02": {
          "statement": "Mutable state (workspace/codebase) is a non-monotone projection derived from truth; projections may be overwritten, recomputed, or replaced.",
          "node_class": "NORMATIVE"
        },
        "TRUTH-AX-03": {
          "statement": "If it cannot be proven via a signed ledger event and evidence digest, it did not happen (within the factory).",
          "node_class": "NORMATIVE"
        }
      },
      "components": {
        "MECH-LEDGER": {
          "name": "Ledger",
          "role": "Topology of truth; append-only, tamper-evident event store.",
          "properties": [
            "append_only",
            "causal_links (DAG)",
            "hash_chained",
            "single_writer + many_readers (implementation detail, not semantic requirement)",
            "typed_events"
          ],
          "law_refs": [
            "LAW-03",
            "LAW-15"
          ],
          "node_class": "NORMATIVE"
        },
        "MECH-CAS": {
          "name": "Content-Addressed Store (CAS)",
          "role": "Data plane for evidence artifacts; deduplication, integrity, progressive disclosure.",
          "properties": [
            "artifact_kind + classification",
            "content_addressing (blake3)",
            "evidence pointers from ledger"
          ],
          "law_refs": [
            "LAW-04",
            "LAW-07",
            "LAW-15"
          ],
          "node_class": "NORMATIVE"
        },
        "MECH-REDUCERS": {
          "name": "Reducers / Projections",
          "role": "Deterministic reconstruction of current state from events; crash-only recovery; audit queries.",
          "properties": [
            "checkpointing/snapshots permitted as derived acceleration",
            "projections are overwritable; facts are not",
            "pure_state_transition (Reducer::apply)"
          ],
          "law_refs": [
            "LAW-03",
            "LAW-11"
          ],
          "node_class": "NORMATIVE"
        }
      },
      "monotone_vs_projection": {
      "monotone_substrate": {
          "statement": "Facts are monotone additions within a declared join-semilattice; truth is the least-upper-bound of all observed events and evidence.",
          "merge_algebra_requirements": [
            "Every domain MUST define a join operator (⊔) that is idempotent, commutative, and associative.",
            "Every fact MUST declare its merge_operator OR conflict_rule_class; unresolvable forks are recorded as ProjectionConflictState.",
            "ProjectionConflictState blocks authoritative promotion until an AdjudicationResolved or ConflictResolutionCommitted event joins the fork.",
            "ordering dependencies must be explicit; hidden ordering is a defect",
            "periodic compaction preserves provenance while controlling replay/MDL"
          ],
          "law_refs": [
            "LAW-03",
            "LAW-10"
          ],
          "node_class": "NORMATIVE"
        },
        "non_monotone_projection": {
          "statement": "Workspaces, codebases, and UIs are projections that can be rewritten; they are not the source of truth.",
          "implications": [
            "audit reconstructs from ledger + evidence, not from narrative",
            "external forge/branch state is not authoritative",
            "filesystem scans are not authoritative for workflow state"
          ],
          "node_class": "EXPLANATORY"
        }
      },
      "node_class": "NORMATIVE"
    },
    "holonic_boundary_model": {
      "definition": "A holon is a Markov-blanketed actor: internal state is ephemeral; interaction occurs only through sensory inputs and active outputs across explicit channels governed by leases, budgets, and policy.",
      "properties": {
        "HB-01": {
          "name": "Seclusion",
          "statement": "Internal state (scratchpad, memory, variables) is private and non-durable; it dies with the process.",
          "node_class": "NORMATIVE"
        },
        "HB-02": {
          "name": "Commitment Filter",
          "statement": "Only selected checkpoints and outputs are committed as durable events/artifacts; commitment is a deliberate boundary crossing.",
          "node_class": "NORMATIVE"
        },
        "HB-03": {
          "name": "Crash-Only Corollary",
          "statement": "If internal entropy becomes high (confusion/errors), terminate and restart from committed state; do not attempt to recover corrupted private state.",
          "node_class": "NORMATIVE"
        },
        "HB-04": {
          "name": "Janus Dualism",
          "statement": "Each holon is simultaneously a whole to its sub-holons and a part to its supervisor; treat sub-holons as you are treated by your supervisor.",
          "node_class": "NORMATIVE"
        },
        "HB-05": {
          "name": "Interface Variety Control",
          "statement": "Supervisors control interface variety (typed signals/contracts), not internal complexity; this resolves Ashby's requisite variety at boundaries.",
          "node_class": "NORMATIVE"
        }
      },
      "channels": {
        "notes": [
          "Channel classes follow Principia Holonica: discovery/handshake/work/evidence.",
          "Each channel has distinct semantics, budgets, retention, and trust posture."
        ],
        "classes": {
          "CH-01": {
            "name": "discovery",
            "trust": "low",
            "bandwidth": "low",
            "primary_value": [
              "capability discovery",
              "uncertainty reduction"
            ],
            "risks": [
              "malformed/malicious inputs",
              "representation attacks"
            ],
            "governance": [
              "bounded by lease/budget",
              "pruned when not valuable"
            ],
            "node_class": "NORMATIVE"
          },
          "CH-02": {
            "name": "handshake",
            "trust": "medium",
            "bandwidth": "low",
            "primary_value": [
              "capability exchange",
              "claim surface establishment",
              "identity exchange"
            ],
            "governance": [
              "audited",
              "explicit authority required"
            ],
            "node_class": "NORMATIVE"
          },
          "CH-03": {
            "name": "work",
            "trust": "contract-bound",
            "bandwidth": "medium",
            "primary_value": [
              "claim/execute/respond on WorkID under contract"
            ],
            "governance": [
              "explicit stop conditions",
              "receipt-backed state transitions",
              "runs under leases and budgets"
            ],
            "node_class": "NORMATIVE"
          },
          "CH-04": {
            "name": "evidence",
            "trust": "high (cryptographic)",
            "bandwidth": "variable",
            "primary_value": [
              "anti-entropy reconciliation",
              "replicate hashes and proofs"
            ],
            "governance": [
              "merge rules + conflict recording",
              "tamper-evident receipts"
            ],
            "node_class": "NORMATIVE"
          }
        },
        "node_class": "NORMATIVE"
      },
      "capability_and_budget": {
        "lease": {
          "statement": "A lease is time-bounded, scope-bounded, revocable authorization to act; work performed without a valid lease is void.",
          "subleasing_rule": "Child leases are strict subsets of parent leases (narrower scope, lower budget).",
          "node_class": "NORMATIVE"
        },
        "budget": {
          "statement": "Budgets bound time/tokens/tool_calls/duration; termination is mandatory on exhaustion.",
          "law_refs": [
            "LAW-06",
            "LAW-12"
          ],
          "node_class": "NORMATIVE"
        },
        "ocap": {
          "statement": "Authority is represented by possession of sealed capability handles; eliminate ambient authority by mediating all effects via tool capabilities.",
          "law_refs": [
            "LAW-05"
          ],
          "node_class": "NORMATIVE"
        },
        "node_class": "NORMATIVE"
      },
      "node_class": "NORMATIVE"
    },
    "control_loops": {
      "stack_model": {
        "statement": "APM2 is a stack of nested control loops: (1) episode loop, (2) work substrate lifecycle loop, (3) recurrence/self-improvement loop.",
        "principle": "Each outer loop treats the inner loop as a plant with measurable outputs and controllable inputs; governance adjusts constraints based on feedback.",
        "law_refs": [
          "LAW-01",
          "LAW-08",
          "LAW-14",
          "LAW-15"
        ],
        "node_class": "NORMATIVE"
      },
      "episode_loop": {
        "id": "LOOP-EPISODE",
        "steps": [
          "observe (ledger/projection/contextpack)",
          "orient (holarchy position, lease validity, budgets, policy)",
          "propose (plan/patch/hypothesis)",
          "actuate (tool calls under OCAP)",
          "verify (gate runs / acceptance checks)",
          "commit (events + evidence pointers + receipts)",
          "stop (success/fail/escalate per stop conditions)"
        ],
        "requirements": [
          "all actuation is auditable as events with receipts",
          "checkpoint intermediate intent-to-act and observations for fine-grained crash-only recovery",
          "bounded exploration under leases; non-convergence is a defect"
        ],
        "law_refs": [
          "LAW-01",
          "LAW-11",
          "LAW-12",
          "LAW-15"
        ],
        "node_class": "NORMATIVE"
      },
      "work_substrate_lifecycle_loop": {
        "id": "LOOP-SUBSTRATE",
        "pipeline": [
          "Intent",
          "Plan drafted/refined",
          "Plan-of-Record approved (digest pinned)",
          "ChangeSet proposed (patch-set / git-bound encoding)",
          "GateRuns executed (rubric + evidence contract)",
          "Findings produced/resolved",
          "Merge acceptance produces MergeReceipt binding inputs->output",
          "Release/runtime telemetry linked back to work + evidence"
        ],
        "principles": [
          "state transitions are authoritative only with gate receipts",
          "Plan-of-Record digest prevents drift by commentary",
          "ChangeSets are identity independent of forge transport artifacts",
          "merge is a governed state transition, not a UI event"
        ],
        "law_refs": [
          "LAW-01",
          "LAW-03",
          "LAW-13",
          "LAW-14",
          "LAW-15"
        ],
        "node_class": "NORMATIVE"
      },
      "recurrence_self_improvement_loop": {
        "id": "LOOP-RECURRENCE",
        "pipeline": [
          "GateRuns and runtime oracles emit Findings/DefectRecords",
          "normalize and fingerprint to compute FindingSignature classes",
          "reducers compute recurrence metrics over windows",
          "threshold triggers Countermeasure work",
          "countermeasure modifies guardrails (schemas/templates/rubrics/safe APIs)",
          "countermeasure validates via corpus replay evidence + rollback plan",
          "governance ratchets policies as verifiers become cheap and reliable"
        ],
        "closure_rule": "A defect closes only with a new/strengthened verifier that would have failed on the original counterexample and now passes, with receipts and evidence captured.",
        "countermeasure_requirements": [
          "MUST ship with a regression corpus of historical finding signatures it eliminates.",
          "MUST include a gate that falsifies the original counterexample in that corpus.",
          "MUST hold out a subset of findings to prevent process-level overfitting (Goodharting)."
        ],
        "zti": {
          "statement": "ZTI applies to scoped implementation tasks; research/discovery holons are exempt. Unplanned context discovery tool calls in scoped tasks are inefficiency defects.",
          "inputs": [
            "ContextPack (bounded, content-addressed, enforceable)",
            "ContextBudget",
            "policy for allowed escalations"
          ]
        },
        "law_refs": [
          "LAW-02",
          "LAW-06",
          "LAW-08",
          "LAW-14"
        ],
        "node_class": "NORMATIVE"
      },
      "node_class": "NORMATIVE"
    },
    "mechanisms": {
      "MECH-CONTEXTPACK": {
        "name": "ContextPack",
        "role": "Compiled, bounded allowlist of context artifacts enabling ZTI actuation.",
        "contracts": [
          "fits ContextBudget",
          "content-addressed",
          "enforceable deny-by-default reads outside pack",
          "sufficient for task completion in scoped implementation episodes"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "ContextPackMiss": true,
              "EvidencePublished": true
            },
            "requires": {
              "WorkOpened": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-CONTEXT-COMPILATION": {
        "name": "Context compilation",
        "role": "Refinement compiler stage that constructs ContextPacks as sufficient-statistics approximations; tool-based exploration in this stage is the work product.",
        "defect_hooks": [
          "pack_miss -> CONTEXT defect",
          "unplanned_context_read -> CONTEXT defect",
          "context_staleness -> CONTEXT+TEMPORAL defect"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "ContextPackMiss": true,
              "DefectRecorded": true,
              "EvidencePublished": true
            },
            "requires": {
              "WorkOpened": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-MDL-BUDGET-REFRACTOR": {
        "name": "MDL-triggered refactoring",
        "role": "Emit refactoring work when API/interface MDL exceeds budget; 'clean code' as cognitive reach requirement.",
        "law_refs": [
          "LAW-06"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "DefectRecorded": true,
              "WorkOpened": true
            },
            "requires": {
              "PolicyLoaded": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-GATES": {
        "name": "Gates + GateRuns",
        "role": "Formal verifiers with rubrics and evidence contracts; GateRuns produce signed receipts and structured findings.",
        "properties": [
          "risk-tiered gate selection",
          "independent verification (AAT as gate)",
          "fail-closed on missing evidence in high-risk tiers"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "EvidencePublished": true,
              "GateReceiptGenerated": true,
              "GateRunCompleted": true,
              "GateRunStarted": true
            },
            "requires": {
              "PolicyLoaded": true
            }
          },
          "receipt_kinds": {
            "emits": {
              "gate.receipt": true
            }
          }
        }
      },
      "MECH-EVIDENCE-BUNDLE": {
        "name": "EvidenceBundle",
        "role": "Content-addressed artifact set sufficient to validate claims; includes provenance and replay semantics.",
        "properties": [
          "content_hash references",
          "classification and progressive disclosure",
          "provenance (inputs, toolchain versions, environment identity)",
          "replay_determinism_class"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "EvidencePublished": true
            },
            "requires": {
              "WorkOpened": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-RECEIPTS": {
        "name": "Receipts (gate, merge, execution, summary)",
        "role": "Signed, machine-readable acceptance proofs binding claims to evidence and inputs/outputs.",
        "properties": [
          "tamper-evident (signed + hash-chained)",
          "binds decision to bundle_hash and input/output digests",
          "required for authoritative promotion"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "CanonicalSnapshotPublished": true,
              "GateReceiptGenerated": true,
              "MergePromoted": true,
              "StopOrderIssued": true,
              "ToolExecuted": true
            }
          },
          "receipt_kinds": {
            "emits": {
              "compaction.receipt": true,
              "gate.receipt": true,
              "merge.receipt": true,
              "stop_order.receipt": true,
              "summary.receipt": true,
              "tool_execution.receipt": true
            }
          }
        }
      },
      "MECH-DETERMINISM-ENVELOPE": {
        "name": "Determinism envelope",
        "role": "Explicit boundary for replayability; nondeterminism is recorded as an input dimension (seed/versions) or treated as a defect.",
        "classes": [
          "deterministic",
          "probabilistic_bounded",
          "non_replayable (treated as verification defect until stabilized)"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "DefectRecorded": true
            },
            "requires": {
              "EvidencePublished": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-SOURCE-SNAPSHOT": {
        "name": "Source snapshots",
        "role": "Frozen world state per episode; repo/lock/policy/model versions pinned by digest.",
        "law_refs": [
          "LAW-09"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "EvidencePublished": true
            },
            "requires": {
              "WorkOpened": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-FRESHNESS-POLICY": {
        "name": "Freshness policy",
        "role": "Defines expiration/drift thresholds by artifact kind and risk tier.",
        "law_refs": [
          "LAW-09",
          "LAW-14"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "PolicyViolation": true
            },
            "requires": {
              "PolicyLoaded": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-IDEMPOTENT-ACTUATION": {
        "name": "Idempotent actuation + dedupe keys",
        "role": "Retry-safe effects; each actuation binds to a dedupe key and emits an execution receipt.",
        "law_refs": [
          "LAW-11"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "ToolExecuted": true,
              "ToolRequested": true
            },
            "requires": {
              "LeaseIssued": true,
              "PolicyLoaded": true
            }
          },
          "receipt_kinds": {
            "emits": {
              "tool_execution.receipt": true
            }
          }
        }
      },
      "MECH-ANTI-ENTROPY": {
        "name": "Anti-entropy protocol",
        "role": "Explicit reconciliation of distributed state; periodic global convergence with conflict recording.",
        "law_refs": [
          "LAW-10"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "DefectRecorded": true
            },
            "requires": {
              "EvidencePublished": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-MERGE-ALGEBRA": {
        "name": "Merge algebra",
        "role": "Declared merge operators or conflict rule classes for facts and receipts to avoid hidden ordering dependencies.",
        "law_refs": [
          "LAW-03",
          "LAW-10"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "DefectRecorded": true,
              "MergePromoted": true
            },
            "requires": {
              "WorkOpened": true
            }
          },
          "receipt_kinds": {
            "emits": {
              "merge.receipt": true
            }
          }
        }
      },
      "MECH-CONFLICT-RECORDING": {
        "name": "Conflict recording as defects",
        "role": "Reconciliation failures are explicit DefectRecords (never silent drops).",
        "law_refs": [
          "LAW-10"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "DefectRecorded": true
            },
            "requires": {
              "LeaseConflict": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-OCAP": {
        "name": "Object-capability (OCAP) isolation",
        "role": "Sealed tool handles constrain authority; prevents ambient authority and confused deputy.",
        "law_refs": [
          "LAW-05"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "PolicyViolation": true,
              "ToolDecided": true
            },
            "requires": {
              "PolicyLoaded": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-LEASES-BUDGETS": {
        "name": "Leases + Budgets",
        "role": "Time/scope bounded authority with resource limits; enforces termination discipline.",
        "law_refs": [
          "LAW-05",
          "LAW-06",
          "LAW-12"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "BudgetExceeded": true,
              "LeaseConflict": true,
              "LeaseExpired": true,
              "LeaseIssued": true,
              "LeaseReleased": true,
              "LeaseRenewed": true
            },
            "requires": {
              "PolicyLoaded": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-POLICY": {
        "name": "Policy adjudication",
        "role": "Default-deny least-privilege tool mediation; risk-tiered gate requirements; waiver governance.",
        "law_refs": [
          "LAW-05",
          "LAW-08",
          "LAW-14"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "BudgetExceeded": true,
              "PolicyLoaded": true,
              "PolicyViolation": true,
              "ToolDecided": true
            },
            "requires": {
              "KeyRotated": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-AUDIT-IDENTITY": {
        "name": "Audit + identity",
        "role": "Every capability use links to stable identity and work ID; enables accountability and non-repudiation.",
        "law_refs": [
          "LAW-05",
          "LAW-15"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "KeyRotated": true
            },
            "requires": {
              "KernelEvent": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-ATTESTATION": {
        "name": "Attestation",
        "role": "Downstream trust is transitive through evidence: artifacts attested as produced under specific toolchains, inputs, and policy versions.",
        "law_refs": [
          "LAW-04",
          "LAW-15"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "GateReceiptGenerated": true
            },
            "requires": {
              "EvidencePublished": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-STOP-CONDITIONS": {
        "name": "Stop conditions",
        "role": "Explicit success/failure/escalate predicates; non-convergence within budget is a defect.",
        "law_refs": [
          "LAW-12"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "BudgetExceeded": true,
              "SessionTerminated": true,
              "WorkAborted": true
            },
            "requires": {
              "PolicyLoaded": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-SEMANTIC-TYPING": {
        "name": "Semantic typing + canonicalization",
        "role": "Typed, unitful, canonical boundary fields; canonical encodings prior to hashing/signing.",
        "law_refs": [
          "LAW-13"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "DefectRecorded": true
            },
            "requires": {
              "WorkOpened": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-ORACLE-REQUEST": {
        "name": "OracleRequest adjudication",
        "role": "Explicit escalation for high-entropy specification gaps; treated as refinement input, not silent out-of-band action.",
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "AdjudicationRequested": true,
              "AdjudicationResolved": true,
              "AdjudicationTimeout": true,
              "AdjudicationVote": true
            },
            "requires": {
              "WorkOpened": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-WORK-DECOMPOSITION": {
        "name": "Holonic decomposition + routing",
        "role": "Coordinator holons decompose goals into low-coupling work graphs; parallelism economics managed via backpressure and verification cost.",
        "math_refs": [
          "Amdahl_law",
          "queueing_theory",
          "backpressure"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "WorkOpened": true,
              "WorkTransitioned": true
            },
            "requires": {
              "LeaseIssued": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-INDEX-LAYERS": {
        "name": "Multi-scale index layers",
        "role": "Hierarchy as compression: stable indices/manifests/summaries route and compress without losing verifiability (deterministic zoom-in).",
        "law_refs": [
          "LAW-07"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "EvidencePublished": true
            },
            "requires": {
              "WorkOpened": true
            }
          },
          "receipt_kinds": {
            "emits": {
              "summary.receipt": true
            }
          }
        }
      },
      "MECH-SCHEMAS": {
        "name": "Versioned strict schemas",
        "role": "Fail-closed schema validation for work objects, receipts, evidence, and policies; schema evolution is compatibility-gated.",
        "law_refs": [
          "LAW-13"
        ],
        "node_class": "NORMATIVE",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "DefectRecorded": true
            },
            "requires": {
              "WorkOpened": true
            }
          },
          "receipt_kinds": {}
        }
      },
      "MECH-EMERGENCY-STOP": {
        "node_class": "NORMATIVE",
        "name": "Emergency stop + root-of-trust stop authority",
        "role": "Factory-wide kill switch: when active, deny all actuation except actions required to observe/verify stop state and to restore safety.",
        "stop_order": {
          "event_kind": "StopOrderIssued",
          "scope_model": {
            "scope_fields": [
              "work_id",
              "session_id",
              "actor_id",
              "tool_name",
              "namespace",
              "global"
            ],
            "default_scope": "global"
          },
          "signer_policy": {
            "root_of_trust_mechanism_ref": "MECH-ROOT-OF-TRUST",
            "required_signer_tier": "ROOT",
            "allowed_signers_hint": [
              "HOLON-KERNEL-GOVERNANCE",
              "HUMAN-ROOT"
            ],
            "key_rotation_event_kind": "KeyRotated"
          },
          "enforcement_points": {
            "fail_closed": true,
            "must_check_before_event_kinds": [
              "ToolRequested",
              "MergePromoted",
              "GateRunStarted",
              "GateReceiptGenerated"
            ],
            "deny_if_unverifiable": true
          },
          "receipts": {
            "receipt_kind": "stop_order.receipt",
            "required_fields": [
              "stop_order_id",
              "scope",
              "issued_at",
              "expires_at",
              "signer",
              "signature",
              "policy_version"
            ]
          }
        },
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "StopOrderCleared": true,
              "StopOrderIssued": true
            },
            "requires": {
              "KeyRotated": true,
              "PolicyLoaded": true
            }
          },
          "receipt_kinds": {
            "emits": {
              "stop_order.receipt": true
            }
          }
        },
        "law_refs": [
          "LAW-01",
          "LAW-05",
          "LAW-12",
          "LAW-15"
        ]
      },
      "MECH-ROOT-OF-TRUST": {
        "node_class": "NORMATIVE",
        "name": "Root of trust (keys, identity, signing policy)",
        "role": "Defines which identities and keys are trusted to sign authoritative receipts and emergency controls; enables key rotation with chain of custody.",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "KeyRotated": true
            }
          },
          "receipt_kinds": {
            "requires": {
              "compaction.receipt": true,
              "gate.receipt": true,
              "merge.receipt": true,
              "stop_order.receipt": true
            }
          }
        },
        "invariants": [
          "All authoritative receipts are verifiable against a trusted key set.",
          "Key rotations are recorded as KeyRotated events that prove control of the old key."
        ],
        "law_refs": [
          "LAW-05",
          "LAW-15"
        ]
      },
      "MECH-COMPACTION": {
        "node_class": "NORMATIVE",
        "name": "Ledger compaction + canonical snapshots",
        "role": "Controls replay cost/MDL by producing verified canonical snapshots that preserve provenance via hash-links and replay-equivalence tests.",
        "fact_bindings": {
          "event_kinds": {
            "emits": {
              "CanonicalSnapshotPublished": true,
              "LedgerCompacted": true
            },
            "requires": {
              "EvidencePublished": true,
              "GateReceiptGenerated": true
            }
          },
          "receipt_kinds": {
            "emits": {
              "compaction.receipt": true
            }
          }
        },
        "invariants": [
          "Snapshot must retain a hash-link to archived history head(s).",
          "Compaction must be accompanied by replay-equivalence evidence over declared queries/projections.",
          "Compaction is governance-scoped and risk-tiered; high-risk streams require stronger evidence."
        ],
        "law_refs": [
          "LAW-03",
          "LAW-06",
          "LAW-07",
          "LAW-15"
        ]
      }
    },
    "invariants": {
      "fundamental": {
        "INV-F-01": {
          "statement": "Authoritative truth is append-only and tamper-evident (hash-chained, signed).",
          "law_refs": [
            "LAW-03",
            "LAW-15"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-02": {
          "statement": "No authoritative state transition occurs without the required gate set producing a machine-readable receipt bound to evidence.",
          "law_refs": [
            "LAW-01",
            "LAW-14",
            "LAW-15"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-03": {
          "statement": "All boundary-relevant fields MUST be typed, unitful, and canonicalized before hashing/signing. All quantitative fields MUST use the Quantity encoding (value_i64 + unit + optional scale). Ambiguous strings at boundaries are defects.",
          "law_refs": [
            "LAW-13"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-04": {
          "statement": "Summaries are lossy claims treated as summary receipts with deterministic evidence pointers; consumers can zoom-in and verify.",
          "law_refs": [
            "LAW-07"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-05": {
          "statement": "Capabilities are default-deny, least-privilege, time/budget bounded; context reads are firewalled with the same rigor as tools.",
          "law_refs": [
            "LAW-05",
            "LAW-12"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-06": {
          "statement": "Actuation is replay-safe under retries (idempotent or compensatable) with receipts and dedupe keys.",
          "law_refs": [
            "LAW-11",
            "LAW-15"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-07": {
          "statement": "Convergence is explicit: merge operators/conflict rules declared; reconciliation failures are recorded as defects.",
          "law_refs": [
            "LAW-03",
            "LAW-10"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-08": {
          "statement": "Freshness is explicit policy; authoritative artifacts are versioned and time-scoped; episodes reason against pinned snapshots.",
          "law_refs": [
            "LAW-09"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-09": {
          "statement": "Budgets and stop conditions are mandatory; unbounded exploration/non-termination is a defect.",
          "law_refs": [
            "LAW-12"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-10": {
          "statement": "Only gate what you can defend: verifiers must be designed for Goodhart resistance with holdouts/adversarial suites; safety constraints are separated from performance objectives.",
          "law_refs": [
            "LAW-08",
            "LAW-14"
          ],
          "node_class": "NORMATIVE"
        },
        "INV-F-11": {
          "node_class": "NORMATIVE",
          "statement": "All actuation paths MUST check stop state. If stop state is missing or unverifiable, deny (fail-closed).",
          "law_refs": [
            "LAW-05",
            "LAW-12",
            "LAW-15"
          ],
          "mechanism_refs": [
            "MECH-EMERGENCY-STOP"
          ]
        },
        "INV-F-12": {
          "node_class": "NORMATIVE",
          "statement": "Any compaction/snapshot MUST preserve auditability: a consumer can reconstruct acceptance decisions via hash-links to archived history and replay-equivalence receipts.",
          "law_refs": [
            "LAW-03",
            "LAW-07",
            "LAW-15"
          ],
          "mechanism_refs": [
            "MECH-COMPACTION"
          ]
        }
      },
      "pragmatic_compromises": {
        "CMP-01": {
          "statement": "SQLite WAL as ledger backend (now) is a replaceable implementation detail as long as event APIs, signatures, and reducer determinism remain stable.",
          "improvement_path": [
            "introduce backend trait",
            "replay test suite for migrations",
            "event API stability policy"
          ],
          "node_class": "EXPLANATORY"
        },
        "CMP-02": {
          "statement": "Length-prefixed JSON over Unix sockets (now) is a transport convenience; long-term, prefer typed canonical encoding for protocol stability and signature determinism.",
          "improvement_path": [
            "canonical JSON (JCS) envelope for signing",
            "protobuf-first IPC schema",
            "strict versioned enums"
          ],
          "node_class": "EXPLANATORY"
        },
        "CMP-03": {
          "statement": "Git and external forges (now) are projections/transport artifacts; internal identities remain ChangeSet/GateRun/MergeReceipt digests independent of forge primitives.",
          "improvement_path": [
            "patch-set canonical encoding",
            "internal forge UI and merge protocol",
            "adapter-only bridge to external forges"
          ],
          "node_class": "EXPLANATORY"
        },
        "CMP-04": {
          "statement": "Human-as-Oracle interventions are required while autonomy is immature; interventions must be explicit Decision/OracleRequest objects to enable later compiler improvement.",
          "improvement_path": [
            "track specification gap defects",
            "extract repeated oracle answers into refinement rules",
            "reduce oracle demand via stronger contracts and better ContextPacks"
          ],
          "node_class": "EXPLANATORY"
        },
        "CMP-05": {
          "statement": "Gate portfolio starts thin for throughput; it thickens as recurrence data justifies and as verifiers become cheap/reliable; enforcement ratchets by governance control loop.",
          "improvement_path": [
            "measure escape rates",
            "compute verifier ROI",
            "stage enforce-with-waiver -> enforce-hard"
          ],
          "node_class": "EXPLANATORY"
        },
        "CMP-06": {
          "statement": "Some artifacts will be non-replayable early (vendor tools, network services); record the boundary and treat it as a verification defect until stabilized.",
          "improvement_path": [
            "record request/response digests where safe",
            "cache tool outputs in CAS",
            "introduce deterministic substitutes or corpora"
          ],
          "node_class": "EXPLANATORY"
        },
        "CMP-07": {
          "statement": "ZTI is aspirational early; enforce progressively as context compilation improves and pack-miss metrics fall.",
          "improvement_path": [
            "context pack compiler feedback from pack-miss",
            "deny-by-default enforcement once compiler reaches sufficiency thresholds",
            "separate research holons from implementation holons"
          ],
          "node_class": "EXPLANATORY"
        }
      }
    },
    "types": {
      "node_class": "NORMATIVE",
      "quantity": {
        "node_class": "NORMATIVE",
        "alignment": {
          "cac_common_type": "cac.common.v1/$defs/quantity",
          "encoding": {
            "value_i64": "int64",
            "unit": "QuantityUnit",
            "scale": "QuantityScale (optional)",
            "kind": "string (optional semantic hint)"
          },
          "meaning": "real_value = value_i64 * (10 ** scale) in unit"
        },
        "unit_enum": {
          "count": {
            "dimension": "count"
          },
          "ms": {
            "dimension": "time"
          },
          "ns": {
            "dimension": "time"
          },
          "s": {
            "dimension": "time"
          },
          "tokens": {
            "dimension": "tokens"
          },
          "bytes": {
            "dimension": "bytes"
          },
          "usd": {
            "dimension": "currency"
          },
          "score": {
            "dimension": "dimensionless"
          }
        },
        "scale_enum": {
          "1e0": {
            "scale": 0
          },
          "1e-3": {
            "scale": -3
          },
          "1e-6": {
            "scale": -6
          },
          "1e-9": {
            "scale": -9
          }
        },
        "law_refs": [
          "LAW-13"
        ]
      },
      "evidence_strength": {
        "node_class": "NORMATIVE",
        "enum": {
          "LOW": {
            "meaning": "Unstructured logs or basic transcripts"
          },
          "MED": {
            "meaning": "Structured tool outputs with digest bindings"
          },
          "HIGH": {
            "meaning": "Verified gate outcomes with independent attestation"
          },
          "FORMAL": {
            "meaning": "Machine-checked proofs or exhaustive hypothesis coverage"
          }
        },
        "law_refs": [
          "LAW-14"
        ]
      },
      "oracle_request": {
        "node_class": "NORMATIVE",
        "schema_id": "apm2.oracle_request.v1",
        "alignment": {
          "proto_hint": "apm2.kernel.v1/AdjudicationRequested",
          "notes": [
            "OracleRequest is a bounded-choice adjudication request used to resolve specification gaps or governance decisions.",
            "Resolution MUST be receipt-backed (evidence + signatures) before resulting rules become NORMATIVE-enforceable."
          ]
        },
        "fields": {
          "oracle_request_id": "string",
          "question_id": "string",
          "work_id": "string",
          "request_type": "enum{BOUNDED_CHOICE,WAIVER,GATE_REVIEW}",
          "inputs": "object (schema-validated; content-addressed pointers preferred)",
          "options": "map<option_id,string_or_object>",
          "decision_deadline": "timestamp",
          "fallback_policy": "string",
          "impact_scope": "object{surfaces:set<string>, max_risk_tier:RiskTier, blast_radius_hint:string}",
          "evidence_refs": "set<content_hash>"
        },
        "law_refs": [
          "LAW-01",
          "LAW-12",
          "LAW-15"
        ]
      },
      "risk_tier": {
        "node_class": "NORMATIVE",
        "enum": {
          "T0": {
            "name": "Experimental",
            "blast_radius": "local/sandbox",
            "notes": [
              "low-risk exploratory work"
            ]
          },
          "T1": {
            "name": "Internal",
            "blast_radius": "factory-internal",
            "notes": [
              "default internal work"
            ]
          },
          "T2": {
            "name": "Production",
            "blast_radius": "user-facing/runtime",
            "notes": [
              "requires stronger gates"
            ]
          },
          "T3": {
            "name": "Security-Critical",
            "blast_radius": "secrets/capabilities/identity",
            "notes": [
              "highest rigor; fail-closed"
            ]
          }
        },
        "law_refs": [
          "LAW-14"
        ]
      },
      "receipt_kind": {
        "node_class": "NORMATIVE",
        "enum": {
          "gate.receipt": {
            "purpose": "proof of gate outcome bound to evidence bundle"
          },
          "merge.receipt": {
            "purpose": "proof of promotion/merge binding inputs->output"
          },
          "tool_execution.receipt": {
            "purpose": "proof of external side effect execution bound to dedupe key"
          },
          "summary.receipt": {
            "purpose": "verifiable summary with evidence pointers"
          },
          "stop_order.receipt": {
            "purpose": "proof of emergency stop state change"
          },
          "compaction.receipt": {
            "purpose": "proof of compaction/snapshot equivalence"
          },
          "permeability.receipt": {
            "purpose": "proof of boundary-crossing knowledge or authority delegation"
          }
        },
        "law_refs": [
          "LAW-07",
          "LAW-15"
        ]
      }
    },
    "risk_model": {
      "node_class": "NORMATIVE",
      "model_id": "RISK-MODEL-V0",
      "risk_tier_enum_ref": "types.risk_tier",
      "gate_catalog": {
        "GATE-STATIC": {
          "node_class": "NORMATIVE",
          "name": "Static analysis / lint / fmt",
          "evidence_contract": "lint_report + compiler_version + inputs_digest"
        },
        "GATE-UNIT": {
          "node_class": "NORMATIVE",
          "name": "Unit/integration tests",
          "evidence_contract": "test_results + command_transcript + env_digest"
        },
        "GATE-AAT": {
          "node_class": "NORMATIVE",
          "name": "Agent Acceptance Testing (independent verifier)",
          "evidence_contract": "aat_receipt + hypotheses + replay metadata"
        },
        "GATE-SECURITY": {
          "node_class": "NORMATIVE",
          "name": "Security scanning + capability checks",
          "evidence_contract": "security_scan + policy_version + capability_manifest_digest"
        },
        "GATE-REPRO": {
          "node_class": "NORMATIVE",
          "name": "Replay / determinism envelope verification",
          "evidence_contract": "replay_receipt + pinned_versions + nondeterminism_boundary"
        },
        "GATE-MERGE": {
          "node_class": "NORMATIVE",
          "name": "Merge admission (produces MergeReceipt)",
          "evidence_contract": "merge_receipt binding inputs->output"
        },
        "GATE-STOP": {
          "node_class": "NORMATIVE",
          "name": "Emergency stop check",
          "evidence_contract": "stop_state_receipt + signer_verification"
        }
      },
      "gate_selection_table": {
        "T0": {
          "node_class": "NORMATIVE",
          "required_evidence_strength": "LOW",
          "required_gates": {
            "GATE-STATIC": {
              "required": true
            }
          }
        },
        "T1": {
          "node_class": "NORMATIVE",
          "required_evidence_strength": "MED",
          "required_gates": {
            "GATE-STATIC": {
              "required": true
            },
            "GATE-UNIT": {
              "required": true
            }
          }
        },
        "T2": {
          "node_class": "NORMATIVE",
          "required_evidence_strength": "HIGH",
          "required_gates": {
            "GATE-STATIC": {
              "required": true
            },
            "GATE-UNIT": {
              "required": true
            },
            "GATE-AAT": {
              "required": true
            },
            "GATE-REPRO": {
              "required": true
            },
            "GATE-STOP": {
              "required": true
            }
          }
        },
        "T3": {
          "node_class": "NORMATIVE",
          "required_evidence_strength": "FORMAL",
          "required_gates": {
            "GATE-STATIC": {
              "required": true
            },
            "GATE-UNIT": {
              "required": true
            },
            "GATE-AAT": {
              "required": true
            },
            "GATE-SECURITY": {
              "required": true
            },
            "GATE-REPRO": {
              "required": true
            },
            "GATE-STOP": {
              "required": true
            }
          },
          "fail_closed": true
        }
      },
      "law_refs": [
        "LAW-14",
        "LAW-08"
      ]
    },
    "event_catalog": {
      "node_class": "NORMATIVE",
      "schema_id": "apm2.kernel.event_kind_catalog.v1",
      "notes": [
        "This is a minimal stable catalog of fact kinds for compiling doctrine into code.",
        "Kinds with proto_ref exist today; kinds marked planned_extension are forward-looking and require schema work."
      ],
      "merge_semantics": {
        "node_class": "NORMATIVE",
        "event_union_rule": "set_union_by_event_hash",
        "ordering_rule": "hash_chain_for_local_sequence; cross-ledger reconciliation requires conflict recording",
        "law_refs": [
          "LAW-03",
          "LAW-10",
          "LAW-15"
        ]
      },
      "event_kinds": {
        "KernelEvent": {
          "node_class": "NORMATIVE",
          "domain": "envelope",
          "proto_ref": "proto/kernel_events.proto#KernelEvent",
          "notes": [
            "Envelope for all stored events; signed; carries actor_id and hash chain."
          ]
        },
        "SessionStarted": {
          "node_class": "NORMATIVE",
          "domain": "session",
          "proto_ref": "proto/kernel_events.proto#SessionStarted"
        },
        "SessionProgress": {
          "node_class": "NORMATIVE",
          "domain": "session",
          "proto_ref": "proto/kernel_events.proto#SessionProgress"
        },
        "SessionTerminated": {
          "node_class": "NORMATIVE",
          "domain": "session",
          "proto_ref": "proto/kernel_events.proto#SessionTerminated"
        },
        "SessionQuarantined": {
          "node_class": "NORMATIVE",
          "domain": "session",
          "proto_ref": "proto/kernel_events.proto#SessionQuarantined"
        },
        "SessionCrashDetected": {
          "node_class": "NORMATIVE",
          "domain": "session",
          "proto_ref": "proto/kernel_events.proto#SessionCrashDetected"
        },
        "SessionRestartScheduled": {
          "node_class": "NORMATIVE",
          "domain": "session",
          "proto_ref": "proto/kernel_events.proto#SessionRestartScheduled"
        },
        "WorkOpened": {
          "node_class": "NORMATIVE",
          "domain": "work",
          "proto_ref": "proto/kernel_events.proto#WorkOpened"
        },
        "WorkTransitioned": {
          "node_class": "NORMATIVE",
          "domain": "work",
          "proto_ref": "proto/kernel_events.proto#WorkTransitioned"
        },
        "WorkCompleted": {
          "node_class": "NORMATIVE",
          "domain": "work",
          "proto_ref": "proto/kernel_events.proto#WorkCompleted"
        },
        "WorkAborted": {
          "node_class": "NORMATIVE",
          "domain": "work",
          "proto_ref": "proto/kernel_events.proto#WorkAborted"
        },
        "WorkPrAssociated": {
          "node_class": "NORMATIVE",
          "domain": "work",
          "proto_ref": "proto/kernel_events.proto#WorkPrAssociated"
        },
        "ToolRequested": {
          "node_class": "NORMATIVE",
          "domain": "tool",
          "proto_ref": "proto/kernel_events.proto#ToolRequested"
        },
        "ToolDecided": {
          "node_class": "NORMATIVE",
          "domain": "tool",
          "proto_ref": "proto/kernel_events.proto#ToolDecided"
        },
        "ToolExecuted": {
          "node_class": "NORMATIVE",
          "domain": "tool",
          "proto_ref": "proto/kernel_events.proto#ToolExecuted"
        },
        "LeaseIssued": {
          "node_class": "NORMATIVE",
          "domain": "lease",
          "proto_ref": "proto/kernel_events.proto#LeaseIssued"
        },
        "LeaseRenewed": {
          "node_class": "NORMATIVE",
          "domain": "lease",
          "proto_ref": "proto/kernel_events.proto#LeaseRenewed"
        },
        "LeaseReleased": {
          "node_class": "NORMATIVE",
          "domain": "lease",
          "proto_ref": "proto/kernel_events.proto#LeaseReleased"
        },
        "LeaseExpired": {
          "node_class": "NORMATIVE",
          "domain": "lease",
          "proto_ref": "proto/kernel_events.proto#LeaseExpired"
        },
        "LeaseConflict": {
          "node_class": "NORMATIVE",
          "domain": "lease",
          "proto_ref": "proto/kernel_events.proto#LeaseConflict"
        },
        "PolicyLoaded": {
          "node_class": "NORMATIVE",
          "domain": "policy",
          "proto_ref": "proto/kernel_events.proto#PolicyLoaded"
        },
        "PolicyViolation": {
          "node_class": "NORMATIVE",
          "domain": "policy",
          "proto_ref": "proto/kernel_events.proto#PolicyViolation"
        },
        "BudgetExceeded": {
          "node_class": "NORMATIVE",
          "domain": "policy",
          "proto_ref": "proto/kernel_events.proto#BudgetExceeded"
        },
        "AdjudicationRequested": {
          "node_class": "NORMATIVE",
          "domain": "adjudication",
          "proto_ref": "proto/kernel_events.proto#AdjudicationRequested"
        },
        "AdjudicationVote": {
          "node_class": "NORMATIVE",
          "domain": "adjudication",
          "proto_ref": "proto/kernel_events.proto#AdjudicationVote"
        },
        "AdjudicationResolved": {
          "node_class": "NORMATIVE",
          "domain": "adjudication",
          "proto_ref": "proto/kernel_events.proto#AdjudicationResolved"
        },
        "AdjudicationTimeout": {
          "node_class": "NORMATIVE",
          "domain": "adjudication",
          "proto_ref": "proto/kernel_events.proto#AdjudicationTimeout"
        },
        "EvidencePublished": {
          "node_class": "NORMATIVE",
          "domain": "evidence",
          "proto_ref": "proto/kernel_events.proto#EvidencePublished"
        },
        "GateReceiptGenerated": {
          "node_class": "NORMATIVE",
          "domain": "evidence",
          "proto_ref": "proto/kernel_events.proto#GateReceiptGenerated"
        },
        "KeyRotated": {
          "node_class": "NORMATIVE",
          "domain": "key",
          "proto_ref": "proto/kernel_events.proto#KeyRotated"
        },
        "DefectRecorded": {
          "node_class": "NORMATIVE",
          "domain": "defect",
          "planned_extension": true
        },
        "ContextPackMiss": {
          "node_class": "NORMATIVE",
          "domain": "context",
          "planned_extension": true
        },
        "GateRunStarted": {
          "node_class": "NORMATIVE",
          "domain": "gate",
          "planned_extension": true
        },
        "GateRunCompleted": {
          "node_class": "NORMATIVE",
          "domain": "gate",
          "planned_extension": true
        },
        "MergePromoted": {
          "node_class": "NORMATIVE",
          "domain": "merge",
          "planned_extension": true
        },
        "StopOrderIssued": {
          "node_class": "NORMATIVE",
          "domain": "stop",
          "planned_extension": true
        },
        "StopOrderCleared": {
          "node_class": "NORMATIVE",
          "domain": "stop",
          "planned_extension": true
        },
        "CanonicalSnapshotPublished": {
          "node_class": "NORMATIVE",
          "domain": "ledger",
          "planned_extension": true
        },
        "LedgerCompacted": {
          "node_class": "NORMATIVE",
          "domain": "ledger",
          "planned_extension": true
        }
      }
    },
    "open_design_questions": {
      "Q-01": {
        "question": "What are the minimal non-negotiable invariants to enforce at runtime (the smallest LAW/INV set everything composes around)?",
        "why_it_matters": "Defines the hard boundary of correctness and safety; everything else is optimization.",
        "provisional_default": [
          "INV-F-01..INV-F-10"
        ],
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-01",
          "question_id": "Q-01",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-02": {
        "question": "What is the canonical unit of trust for downstream holons: EventRecord only, or EvidenceBundle+Verifier attestation, and when is each required?",
        "why_it_matters": "Defines transitive trust; impacts storage, verification cost, and audit completeness.",
        "provisional_default": "Treat EventRecord as routing fact; treat EvidenceBundle+Receipt as acceptance fact for any authoritative transition.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-02",
          "question_id": "Q-02",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-03": {
        "question": "How is 'context sufficiency' operationalized and measured (beyond subjective judgment)?",
        "why_it_matters": "Bounded context is a primary failure driver; must be controlled via measurable surrogates.",
        "provisional_default": "Adopt LAW-02 control objectives: pack-miss, unplanned tool calls, defect escape correlation, stuck proxies.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-03",
          "question_id": "Q-03",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-04": {
        "question": "What is the freshness policy: which artifacts must be temporally pinned, and where is pinning stored/verified (ledger fields vs evidence artifacts)?",
        "why_it_matters": "Non-stationarity creates silent invalidation; pinning is required for replay and correctness.",
        "provisional_default": "Pin per episode: repo digest + dependency locks + toolchain versions + policy version; store pins in evidence + reference from events.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-04",
          "question_id": "Q-04",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-05": {
        "question": "Where should gated promotion live: reducers, daemon handlers, tool-policy, or explicit GateRun work objects?",
        "why_it_matters": "Defines who can block/allow authoritative transitions and how proofs are attached.",
        "provisional_default": "Represent verification as explicit GateRun objects that emit receipts; reducers enforce that transitions require receipts by risk tier.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-05",
          "question_id": "Q-05",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-06": {
        "question": "What is the merge semantics model: are conflicts first-class events with explicit merge receipts, and what is the minimal audit-complete merge receipt?",
        "why_it_matters": "Convergence and non-repudiation depend on explicit merge semantics.",
        "provisional_default": "MergeReceipt binds (Plan-of-Record digest, ChangeSet digest, GateRun receipt digests, approver identity) -> output repo state digest.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-06",
          "question_id": "Q-06",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-07": {
        "question": "Which tool executions must be exactly-once vs at-least-once, and how is dedupe keyed?",
        "why_it_matters": "Retry safety and external side effects require idempotency and accounting.",
        "provisional_default": "Assume at-least-once delivery; require dedupe keys and execution receipts for all external effects.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-07",
          "question_id": "Q-07",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-08": {
        "question": "What is the budget model: per episode, per session, per work object, and what triggers escalation vs termination?",
        "why_it_matters": "Bounded search and termination discipline are foundational; budgets encode priorities and risk posture.",
        "provisional_default": "Episode budgets enforce immediate termination; session/work budgets govern escalation and scheduling (hardening, countermeasures).",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-08",
          "question_id": "Q-08",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-09": {
        "question": "How is verifier economics managed: how do you prevent Goodharting gates and decide when a verifier becomes mandatory?",
        "why_it_matters": "Proxy gaps are exploited under optimization pressure; gating must be defendable and cost-effective.",
        "provisional_default": "Separate safety invariants from performance; maintain holdouts/adversarial suites; ratchet based on measured escape rates and verifier ROI.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-09",
          "question_id": "Q-09",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-10": {
        "question": "How do you define defect closure: what constitutes 'closed loop' remediation and who can waive it?",
        "why_it_matters": "Without closure rules, defects become narrative; recurrence remains high.",
        "provisional_default": "Defect closes only with strengthened verifier passing on original counterexample; waivers are explicit Decision objects with expiry.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-10",
          "question_id": "Q-10",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-11": {
        "question": "What are the top expected defect classes early and which countermeasures should be pre-built?",
        "why_it_matters": "Early-stage defects are predictable (context omission, stale projections, tool misuse, prompt injection) and are best addressed systemically.",
        "provisional_default": [
          "context_pack_miss tracking and compiler feedback",
          "capability overgrant detection",
          "flakiness stabilization gates",
          "merge conflict recording"
        ],
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-11",
          "question_id": "Q-11",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-12": {
        "question": "What is the trust boundary between adapter observations and ledger truth: can adapters emit events directly or only propose observations that must be verified?",
        "why_it_matters": "Adapters sit on untrusted surfaces; event authority must not be compromised by observation noise.",
        "provisional_default": "Adapters propose observations; authoritative events require verification/attestation or trusted identity tier.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-12",
          "question_id": "Q-12",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-13": {
        "question": "How strict is OCAP in practice: are tools always default-deny with explicit leases, and is read-only mode first-class?",
        "why_it_matters": "Capability containment is the primary security primitive; read-only sessions reduce blast radius.",
        "provisional_default": "Default-deny always; read-only lease profiles are first-class and the default for review/audit.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-13",
          "question_id": "Q-13",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-14": {
        "question": "Where do humans enter the loop by design (explicit adjudication points)?",
        "why_it_matters": "Human bandwidth is scarce; the system must request adjudication only at sharp points with bounded options and attached evidence.",
        "provisional_default": [
          "policy changes",
          "high-risk gate waivers",
          "merge approvals for high tiers",
          "credential/profile changes",
          "incident response decisions"
        ],
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-14",
          "question_id": "Q-14",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      },
      "Q-15": {
        "question": "What is the primary success metric for early stages: throughput, correctness, safety, replayability?",
        "why_it_matters": "Metric choice shapes incentives and gate design; premature throughput optimization is a common failure mode.",
        "provisional_default": "Prioritize recurrence reduction and replayability (stability) before raw throughput.",
        "node_class": "EXPLANATORY",
        "oracle_request": {
          "schema_id": "apm2.oracle_request.v1",
          "oracle_request_id": "ORQ-Q-15",
          "question_id": "Q-15",
          "work_id": "DOC-HOLONIC-UNIFIED-THEORY-0001",
          "request_type": "BOUNDED_CHOICE",
          "inputs": {},
          "options": {},
          "decision_deadline": null,
          "fallback_policy": "ESCALATE",
          "impact_scope": {},
          "evidence_refs": []
        }
      }
    },
    "provisional_defaults": {
      "DEF-01": {
        "name": "Unit of truth",
        "statement": "Truth = ledger events + content-addressed artifacts; anything not bound by digest/receipt is non-authoritative.",
        "status": "provisional",
        "node_class": "NORMATIVE",
        "maturity": "PROVISIONAL"
      },
      "DEF-02": {
        "name": "Context sufficiency",
        "statement": "ContextPack is the compiled sufficient-statistics artifact; measure sufficiency via LAW-02 surrogates and treat pack misses as defects.",
        "status": "provisional",
        "node_class": "NORMATIVE",
        "maturity": "PROVISIONAL"
      },
      "DEF-03": {
        "name": "Freshness",
        "statement": "Pin world state per episode (repo+locks+policy+toolchain+model versions); enforce expirations by risk tier.",
        "status": "provisional",
        "node_class": "NORMATIVE",
        "maturity": "PROVISIONAL"
      },
      "DEF-04": {
        "name": "Merge semantics",
        "statement": "Require MergeReceipt binding input digests and gate receipts to output repo digest; conflicts are explicit events/defects.",
        "status": "provisional",
        "node_class": "NORMATIVE",
        "maturity": "PROVISIONAL"
      },
      "DEF-05": {
        "name": "Idempotency",
        "statement": "Assume at-least-once for all actuation; require dedupe keys and receipts for external effects.",
        "status": "provisional",
        "node_class": "NORMATIVE",
        "maturity": "PROVISIONAL"
      },
      "DEF-06": {
        "name": "Governance ratchet",
        "statement": "Start in observe mode; move to enforce-with-waiver; then enforce-hard as verifiers become reliable and cheap.",
        "status": "provisional",
        "node_class": "NORMATIVE",
        "maturity": "PROVISIONAL"
      },
      "DEF-07": {
        "name": "Early success metric",
        "statement": "Optimize for stability: recurrence reduction + replayability; treat throughput optimization as unsafe until loops are stable.",
        "status": "provisional",
        "node_class": "NORMATIVE",
        "maturity": "PROVISIONAL"
      }
    },
    "metrics_and_signals": {
      "context_sufficiency": {
        "MET-CTX-01": {
          "name": "pack_miss_rate",
          "definition": "Fraction of episodes requiring context outside the provided ContextPack.",
          "node_class": "NORMATIVE"
        },
        "MET-CTX-02": {
          "name": "unplanned_context_tool_calls",
          "definition": "Count of tool calls executed primarily to discover missing context during scoped implementation episodes.",
          "node_class": "NORMATIVE"
        },
        "MET-CTX-03": {
          "name": "defect_escape_rate_context_correlated",
          "definition": "Rate of downstream defects correlated with missing/stale context indicators.",
          "node_class": "NORMATIVE"
        },
        "MET-CTX-04": {
          "name": "stuck_proxies",
          "definition": "Rollbacks, retries, resets, and non-convergent loops as proxies for context poverty.",
          "node_class": "NORMATIVE"
        },
        "MET-CTX-05": {
          "name": "toolcall_information_gain_proxy",
          "definition": "Binary metric: did a discovery tool call result in a material diff in the proposed plan or patch? Measures information value of exploration.",
          "node_class": "NORMATIVE"
        },
        "MET-CTX-06": {
          "name": "counterfactual_pack_eval",
          "definition": "Offline evaluation scoring: relative gate pass rate improvement when comparing Pack vN vs vN+1 on the same task corpus.",
          "node_class": "NORMATIVE"
        }
      },
      "verification_economics": {
        "MET-VER-01": {
          "name": "escape_rate_by_gate_set",
          "definition": "Probability of defect escape to later stages given a gate portfolio.",
          "node_class": "NORMATIVE"
        },
        "MET-VER-02": {
          "name": "gate_cost",
          "definition": "Expected C_U + C_L cost per gate run (compute/time/tool calls).",
          "node_class": "NORMATIVE"
        },
        "MET-VER-03": {
          "name": "false_positive_rate",
          "definition": "Rate of incorrect failures; impacts throughput and bypass incentives.",
          "node_class": "NORMATIVE"
        },
        "MET-VER-04": {
          "name": "proxy_gap_indicators",
          "definition": "Signals of Goodharting (overfitting to gates, holdout failures, adversarial suite regressions).",
          "node_class": "NORMATIVE"
        }
      },
      "recurrence_reduction": {
        "MET-REC-01": {
          "name": "finding_signature_rate",
          "definition": "Counts/rates of FindingSignature classes over time windows.",
          "node_class": "NORMATIVE"
        },
        "MET-REC-02": {
          "name": "time_to_resolution",
          "definition": "Time from finding/defect to closure evidence.",
          "node_class": "NORMATIVE"
        },
        "MET-REC-03": {
          "name": "post_countermeasure_delta",
          "definition": "Before/after recurrence delta attributable to a countermeasure, validated via corpus replay.",
          "node_class": "NORMATIVE"
        }
      },
      "security_and_containment": {
        "MET-SEC-01": {
          "name": "capability_overgrant_events",
          "definition": "Occurrences where tools or scopes exceeded declared least authority.",
          "node_class": "NORMATIVE"
        },
        "MET-SEC-02": {
          "name": "context_firewall_violations",
          "definition": "Attempts to read outside ContextPacks; includes denied reads.",
          "node_class": "NORMATIVE"
        },
        "MET-SEC-03": {
          "name": "receipt_integrity_failures",
          "definition": "Missing/invalid signatures, hash mismatches, or evidence omission at required boundaries.",
          "node_class": "NORMATIVE"
        }
      },
      "search_stability": {
        "MET-SRCH-01": {
          "name": "progress_potential",
          "definition": "Composite metric of windowed novelty (no plan/patch hash change), repeated action patterns, and open-obligation count delta.",
          "node_class": "NORMATIVE"
        }
      },
      "merge_and_convergence": {
        "MET-MRG-01": {
          "name": "merge_conflict_rate",
          "definition": "Frequency of merge conflicts by subsystem/interface; informs decomposition and interface stabilization work.",
          "node_class": "NORMATIVE"
        },
        "MET-MRG-02": {
          "name": "conflict_recording_completeness",
          "definition": "Fraction of reconciliation failures producing explicit DefectRecords (target = 1.0).",
          "node_class": "NORMATIVE"
        }
      }
    },
    "documentation_integration": {
      "doc_spine": {
        "DOC-SPINE-01": {
          "title": "Physics",
          "contents": [
            "bounded context and MDL",
            "stochastic cognition",
            "non-stationarity and freshness",
            "distributed failure and convergence",
            "adversarial representation and containment",
            "computability + search limits"
          ],
          "node_class": "EXPLANATORY"
        },
        "DOC-SPINE-02": {
          "title": "Substrate",
          "contents": [
            "ledger + CAS + reducers",
            "truth vs projection",
            "merge algebra and compaction",
            "measurement integrity"
          ],
          "node_class": "EXPLANATORY"
        },
        "DOC-SPINE-03": {
          "title": "Boundary",
          "contents": [
            "holons, Markov blanket, commitment filter",
            "leases/budgets/stop conditions",
            "OCAP tools and policies",
            "checkpointing and crash-only recovery",
            "channel classes and selective permeability"
          ],
          "node_class": "EXPLANATORY"
        },
        "DOC-SPINE-04": {
          "title": "Loops",
          "contents": [
            "episode loop",
            "work lifecycle loop (Plan->ChangeSet->GateRun->MergeReceipt)",
            "recurrence loop (Findings->Countermeasures)"
          ],
          "node_class": "EXPLANATORY"
        },
        "DOC-SPINE-05": {
          "title": "Laws as Corollaries",
          "contents": [
            "LAW-01..LAW-15 mapping to mechanisms and invariants"
          ],
          "node_class": "EXPLANATORY"
        },
        "DOC-SPINE-06": {
          "title": "Core Objects",
          "contents": [
            "Plan-of-Record + SpecSnapshot",
            "ChangeSet + patch-set encoding",
            "Gate + GateRun + GateReceipt",
            "EvidenceBundle",
            "Finding + FindingSignature",
            "Countermeasure",
            "MergeReceipt",
            "Decision/Question/OracleRequest"
          ],
          "node_class": "EXPLANATORY"
        }
      },
      "module_contract_template": {
        "required_fields": [
          "module_role_in_spine (physics/substrate/boundary/loop)",
          "laws_upheld (LAW-xx list)",
          "invariants (INV-F-xx list)",
          "inputs_outputs (typed boundary signals)",
          "failure_modes (defect surfaces)",
          "metrics (which signals this module produces/consumes)"
        ],
        "goal": "Every AGENTS.md begins by stating which part of the spine it implements and which laws it enforces.",
        "node_class": "NORMATIVE"
      },
      "doc_spine_order": [
        "DOC-SPINE-01",
        "DOC-SPINE-02",
        "DOC-SPINE-03",
        "DOC-SPINE-04",
        "DOC-SPINE-05",
        "DOC-SPINE-06"
      ]
    },
    "law_alignment": {
      "laws": {
        "LAW-01": {
          "name": "Loop Closure & Gated Promotion",
          "reference_path": "references/law_01.md",
          "role": "Defines authoritative promotion: no shared truth transition without verification receipts.",
          "node_class": "NORMATIVE"
        },
        "LAW-02": {
          "name": "Observable Context Sufficiency",
          "reference_path": "references/law_02.md",
          "role": "Defines measurable surrogates for context sufficiency; drives context compiler optimization.",
          "node_class": "NORMATIVE"
        },
        "LAW-03": {
          "name": "Monotone Ledger vs. Overwritable Projection",
          "reference_path": "references/law_03.md",
          "role": "Separates truth substrate from mutable projections; requires merge algebra and compaction discipline.",
          "node_class": "NORMATIVE"
        },
        "LAW-04": {
          "name": "Stochastic Stability",
          "reference_path": "references/law_04.md",
          "role": "Binds stability to contract+receipt+evidence; flakiness is a first-class defect.",
          "node_class": "NORMATIVE"
        },
        "LAW-05": {
          "name": "Dual-Axis Containment",
          "reference_path": "references/law_05.md",
          "role": "Authority confinement + identity/audit; context read firewalls and confused deputy prevention.",
          "node_class": "NORMATIVE"
        },
        "LAW-06": {
          "name": "MDL as a Gated Budget",
          "reference_path": "references/law_06.md",
          "role": "MDL budgets enforce cognitive reach; triggers decomposition/refactoring when exceeded.",
          "node_class": "NORMATIVE"
        },
        "LAW-07": {
          "name": "Verifiable Summaries",
          "reference_path": "references/law_07.md",
          "role": "Summaries are receipts with evidence pointers and deterministic zoom-in.",
          "node_class": "NORMATIVE"
        },
        "LAW-08": {
          "name": "Verifier Economics (Goodhart Resistance)",
          "reference_path": "references/law_08.md",
          "role": "Only gate what you can defend; holdouts/adversarial suites; safety constraints separated from performance targets.",
          "node_class": "NORMATIVE"
        },
        "LAW-09": {
          "name": "Temporal Pinning & Freshness",
          "reference_path": "references/law_09.md",
          "role": "Versioned/time-scoped artifacts; frozen snapshots for episodes; explicit drift handling.",
          "node_class": "NORMATIVE"
        },
        "LAW-10": {
          "name": "Anti-Entropy & Merge Semantics",
          "reference_path": "references/law_10.md",
          "role": "Convergence requires explicit merge operators and conflict recording; periodic reconciliation.",
          "node_class": "NORMATIVE"
        },
        "LAW-11": {
          "name": "Conservation of Work and Idempotent Actuation",
          "reference_path": "references/law_11.md",
          "role": "Actuation must be retry-safe; dedupe keys and execution receipts.",
          "node_class": "NORMATIVE"
        },
        "LAW-12": {
          "name": "Bounded Search and Termination Discipline",
          "reference_path": "references/law_12.md",
          "role": "Exploration runs under leases and stop conditions; non-convergence is a defect.",
          "node_class": "NORMATIVE"
        },
        "LAW-13": {
          "name": "Semantic Contracting",
          "reference_path": "references/law_13.md",
          "role": "Typed/unitful/canonical boundaries; versioned enums; canonicalization before hashing/signing. Includes canonical Quantity encoding for all quantitative fields.",
          "node_class": "NORMATIVE"
        },
        "LAW-14": {
          "name": "Proportionality and Risk-Weighted Evidence",
          "reference_path": "references/law_14.md",
          "role": "Gate strength scales with risk/blast radius; adaptive enforcement based on escape rates.",
          "node_class": "NORMATIVE"
        },
        "LAW-15": {
          "name": "Measurement Integrity",
          "reference_path": "references/law_15.md",
          "role": "Receipts are tamper-evident; omission of required evidence is a defect; fail-closed in high-risk transitions.",
          "node_class": "NORMATIVE"
        }
      },
      "law_order": [
        "LAW-01",
        "LAW-02",
        "LAW-03",
        "LAW-04",
        "LAW-05",
        "LAW-06",
        "LAW-07",
        "LAW-08",
        "LAW-09",
        "LAW-10",
        "LAW-11",
        "LAW-12",
        "LAW-13",
        "LAW-14",
        "LAW-15"
      ]
    },
    "glossary_alignment": {
      "canonical_terms": {
        "Holon": {
          "ref": "documents/skills/glossary/references/holon.md",
          "node_class": "BACKGROUND"
        },
        "Ledger": {
          "ref": "documents/skills/glossary/references/ledger.md",
          "node_class": "BACKGROUND"
        },
        "Work Substrate": {
          "ref": "documents/skills/glossary/references/work_substrate.md",
          "node_class": "BACKGROUND"
        },
        "Plan": {
          "ref": "documents/skills/glossary/references/plan.md",
          "node_class": "BACKGROUND"
        },
        "ChangeSet": {
          "ref": "documents/skills/glossary/references/change_set.md",
          "node_class": "BACKGROUND"
        },
        "Gate": {
          "ref": "documents/skills/glossary/references/gate.md",
          "node_class": "BACKGROUND"
        },
        "Evidence": {
          "ref": "documents/skills/glossary/references/evidence.md",
          "node_class": "BACKGROUND"
        },
        "Finding": {
          "ref": "documents/skills/glossary/references/finding.md",
          "node_class": "BACKGROUND"
        },
        "Countermeasure": {
          "ref": "documents/skills/glossary/references/countermeasure.md",
          "node_class": "BACKGROUND"
        },
        "Merge Receipt": {
          "ref": "documents/skills/glossary/references/merge_receipt.md",
          "node_class": "BACKGROUND"
        },
        "Lease/Budget": {
          "ref": "documents/skills/glossary/references/lease_and_budget.md",
          "node_class": "BACKGROUND"
        },
        "OCAP": {
          "ref": "documents/skills/glossary/references/ocap.md",
          "node_class": "BACKGROUND"
        },
        "Checkpointing": {
          "ref": "documents/skills/glossary/references/checkpointing.md",
          "node_class": "BACKGROUND"
        },
        "ContextPack": {
          "ref": "documents/skills/glossary/references/context_pack.md",
          "node_class": "BACKGROUND"
        },
        "Commitment Filter": {
          "ref": "documents/skills/glossary/references/commitment_filter.md",
          "node_class": "BACKGROUND"
        },
        "Oracle": {
          "ref": "documents/skills/glossary/references/oracle.md",
          "node_class": "BACKGROUND"
        },
        "Interface Variety": {
          "ref": "documents/skills/glossary/references/interface_variety.md",
          "node_class": "BACKGROUND"
        },
        "Zero-Tool Ideal (ZTI)": {
          "ref": "documents/skills/glossary/references/zti.md",
          "node_class": "BACKGROUND"
        }
      }
    },
    "references": {
      "primary_documents": {
        "laws-of-holonic-agent-systems": {
          "ref": "documents/skills/laws-of-holonic-agent-systems/SKILL.md",
          "node_class": "BACKGROUND"
        },
        "agent-native-software (holonic-agent-network)": {
          "ref": "documents/skills/laws-of-holonic-agent-systems/references/holonic-agent-network/references/agent-native-software.md",
          "node_class": "BACKGROUND"
        },
        "agent-native-software (industry textbook)": {
          "ref": "documents/skills/laws-of-holonic-agent-systems/references/agent-native-software/SKILL.md",
          "node_class": "BACKGROUND"
        },
        "defects textbook": {
          "ref": "documents/skills/laws-of-holonic-agent-systems/references/holonic-agent-system-defects/SKILL.md",
          "node_class": "BACKGROUND"
        },
        "glossary": {
          "ref": "documents/skills/glossary/SKILL.md",
          "node_class": "BACKGROUND"
        }
      }
    }
  },
  "schema": "apm2.holonic.unified_theory.v1",
  "schema_version": "1.0.0"
}
