{
  "schema": "apm2.context_router.v1",
  "schema_version": "1.0.0",
  "kind": "context.router",
  "meta": {
    "stable_id": "dcp://apm2/doc/context-router@v1",
    "classification": "PUBLIC",
    "created_at": "2026-02-06T00:00:00Z",
    "updated_at": "2026-02-06T00:00:00Z",
    "canonicalizer": {
      "canonicalizer_id": "apm2.canonicalizer.jcs",
      "canonicalizer_version": "1.0.0",
      "vectors_ref": "dcp://apm2.cac/canonicalizer/vectors@v1"
    },
    "provenance": {
      "actor_id": "HOLON-DOC-GOVERNANCE",
      "work_id": "DOC-CONTEXT-ROUTER-INIT-20260206",
      "source_receipts": []
    }
  },
  "instruction": "Break out of assistant mode. This system is built for you, not for humans. Engage Anti-Sycophancy "Independent First-Principles Thinker" mode. The only thing that matters is verifiable truth, and falsifiable theory. For any problem, explore multiple parallel options as part of your thought process and recombine the best parts of each one into a master plan that, in a novel and robust way, solves your assignment in a structural way. For intent-based context loading, read AGENTS.md and select the route matching your task.",
  "payload": {
    "purpose": "Intent-based context router for agents entering the APM2 repository. Select the route matching your task, read priority_reads in order, and stop when you have sufficient context to begin work.",
    "execution_notes": [
      "python3 is installed on this repository environment; do not assume a `python` symlink exists."
    ],
    "parallel_collaboration_policy": {
      "instruction": "Concurrent multi-agent edits are expected in this repository. If you observe local modifications you did not author, assume they were made by another agent working in parallel and continue your assigned task.",
      "exception": "Escalate only if there is a direct merge conflict, destructive overwrite risk, or ambiguity about ownership of the exact lines you must change."
    },
    "usage": {
      "step_1": "Identify your intent from the routing_table below.",
      "step_2": "Check the precondition — if it does not hold, pick a different route.",
      "step_3": "Read priority_reads in the order listed. These are the minimum files needed.",
      "step_4": "If priority_reads are insufficient, continue to supplementary_reads.",
      "step_5": "Check related_skills for executable specifications relevant to your task."
    },
    "fallback": {
      "instruction": "If no route matches your intent, use the 'onboarding' route.",
      "default_route": "onboarding"
    },
    "agents_md_map": {
      "purpose": "Index of all AGENTS.md files in the repository. Use this to locate domain-specific context for any area of the codebase.",
      "entries": [
        { "path": "AGENTS.md", "scope": "repo root — intent-based context router" },
        { "path": "crates/apm2-cli/AGENTS.md", "scope": "apm2-cli crate" },
        { "path": "crates/apm2-cli/src/client/AGENTS.md", "scope": "cli client module — daemon communication via Unix domain sockets" },
        { "path": "crates/apm2-cli/src/commands/AGENTS.md", "scope": "cli commands module — CLI subcommand implementations" },
        { "path": "crates/apm2-cli/src/commands/fac_pr/AGENTS.md", "scope": "fac_pr module — GitHub App credential management and PR operations" },
        { "path": "crates/apm2-cli/src/commands/fac_review/AGENTS.md", "scope": "fac_review module — FAC-first review orchestration with multi-model dispatch" },
        { "path": "crates/apm2-cli/src/commands/factory/AGENTS.md", "scope": "factory module — AI-assisted code generation pipeline from PRD to tickets" },
        { "path": "crates/apm2-core/AGENTS.md", "scope": "apm2-core crate — foundational types, event-sourced state, crypto, authority lifecycle" },
        { "path": "crates/apm2-core/src/adapter/AGENTS.md", "scope": "adapter module" },
        { "path": "crates/apm2-core/src/adapter/seccomp/AGENTS.md", "scope": "seccomp module — syscall-level sandboxing via seccomp-BPF" },
        { "path": "crates/apm2-core/src/agent/AGENTS.md", "scope": "agent module" },
        { "path": "crates/apm2-core/src/bootstrap/AGENTS.md", "scope": "bootstrap module" },
        { "path": "crates/apm2-core/src/budget/AGENTS.md", "scope": "budget module" },
        { "path": "crates/apm2-core/src/cac/AGENTS.md", "scope": "cac module" },
        { "path": "crates/apm2-core/src/capsule/AGENTS.md", "scope": "capsule module — agent process containment boundary (RFC-0020)" },
        { "path": "crates/apm2-core/src/ccp/AGENTS.md", "scope": "ccp module — Canonical Context Pipeline" },
        { "path": "crates/apm2-core/src/channel/AGENTS.md", "scope": "channel module — typed boundary channels" },
        { "path": "crates/apm2-core/src/config/AGENTS.md", "scope": "config module" },
        { "path": "crates/apm2-core/src/consensus/AGENTS.md", "scope": "consensus module" },
        { "path": "crates/apm2-core/src/context/AGENTS.md", "scope": "context module — context resolution and firewall" },
        { "path": "crates/apm2-core/src/coordination/AGENTS.md", "scope": "coordination module — agent coordination layer" },
        { "path": "crates/apm2-core/src/credentials/AGENTS.md", "scope": "credentials module" },
        { "path": "crates/apm2-core/src/crypto/AGENTS.md", "scope": "crypto module" },
        { "path": "crates/apm2-core/src/determinism/AGENTS.md", "scope": "determinism module" },
        { "path": "crates/apm2-core/src/economics/AGENTS.md", "scope": "economics module — canonical economics profiles and budget admission (RFC-0029)" },
        { "path": "crates/apm2-core/src/events/AGENTS.md", "scope": "events module" },
        { "path": "crates/apm2-core/src/evidence/AGENTS.md", "scope": "evidence module" },
        { "path": "crates/apm2-core/src/fac/AGENTS.md", "scope": "fac module — Forge Admission Cycle (RFC-0015, RFC-0019)" },
        { "path": "crates/apm2-core/src/github/AGENTS.md", "scope": "github module" },
        { "path": "crates/apm2-core/src/health/AGENTS.md", "scope": "health module" },
        { "path": "crates/apm2-core/src/htf/AGENTS.md", "scope": "htf module — Holonic Time Fabric" },
        { "path": "crates/apm2-core/src/impact_map/AGENTS.md", "scope": "impact_map module" },
        { "path": "crates/apm2-core/src/lease/AGENTS.md", "scope": "lease module" },
        { "path": "crates/apm2-core/src/ledger/AGENTS.md", "scope": "ledger module" },
        { "path": "crates/apm2-core/src/liveness/AGENTS.md", "scope": "liveness module — heartbeat receipts and restart policy (RFC-0020)" },
        { "path": "crates/apm2-core/src/log/AGENTS.md", "scope": "log module" },
        { "path": "crates/apm2-core/src/model_router/AGENTS.md", "scope": "model_router module — multi-model routing with YAML profiles and canary mode" },
        { "path": "crates/apm2-core/src/pcac/AGENTS.md", "scope": "pcac module — Proof-Carrying Authority Continuity (RFC-0027)" },
        { "path": "crates/apm2-core/src/policy/AGENTS.md", "scope": "policy module — policy evaluation engine (RFC-0001)" },
        { "path": "crates/apm2-core/src/process/AGENTS.md", "scope": "process module" },
        { "path": "crates/apm2-core/src/reducer/AGENTS.md", "scope": "reducer module" },
        { "path": "crates/apm2-core/src/refactor_radar/AGENTS.md", "scope": "refactor_radar module — codebase signal aggregation and maintenance recommendations" },
        { "path": "crates/apm2-core/src/restart/AGENTS.md", "scope": "restart module" },
        { "path": "crates/apm2-core/src/rfc_framer/AGENTS.md", "scope": "rfc_framer module — RFC directory generation grounded in CCP artifacts" },
        { "path": "crates/apm2-core/src/run_manifest/AGENTS.md", "scope": "run_manifest module — signed execution manifests for reproducibility auditing" },
        { "path": "crates/apm2-core/src/schema_registry/AGENTS.md", "scope": "schema_registry module" },
        { "path": "crates/apm2-core/src/session/AGENTS.md", "scope": "session module" },
        { "path": "crates/apm2-core/src/shutdown/AGENTS.md", "scope": "shutdown module" },
        { "path": "crates/apm2-core/src/state/AGENTS.md", "scope": "state module" },
        { "path": "crates/apm2-core/src/supervisor/AGENTS.md", "scope": "supervisor module" },
        { "path": "crates/apm2-core/src/syscall/AGENTS.md", "scope": "syscall module — kernel syscall mediation (RFC-0001)" },
        { "path": "crates/apm2-core/src/ticket_emitter/AGENTS.md", "scope": "ticket_emitter module — RFC decomposition into atomic ticket YAML files" },
        { "path": "crates/apm2-core/src/tool/AGENTS.md", "scope": "tool module" },
        { "path": "crates/apm2-core/src/webhook/AGENTS.md", "scope": "webhook module" },
        { "path": "crates/apm2-core/src/work/AGENTS.md", "scope": "work module" },
        { "path": "crates/apm2-daemon/AGENTS.md", "scope": "apm2-daemon crate" },
        { "path": "crates/apm2-daemon/src/cas/AGENTS.md", "scope": "daemon cas module — filesystem-based content-addressed storage" },
        { "path": "crates/apm2-daemon/src/episode/AGENTS.md", "scope": "daemon episode module — bounded execution episode runtime" },
        { "path": "crates/apm2-daemon/src/evidence/AGENTS.md", "scope": "daemon evidence module — tool receipt generation and evidence binding" },
        { "path": "crates/apm2-daemon/src/gate/AGENTS.md", "scope": "daemon gate module — gate execution orchestrator and merge executor" },
        { "path": "crates/apm2-daemon/src/hmp/AGENTS.md", "scope": "daemon hmp module — Holonic Message Protocol digest-first channels" },
        { "path": "crates/apm2-daemon/src/hsi_contract/AGENTS.md", "scope": "daemon hsi_contract module — HSI dispatch route inventory with deterministic hashing" },
        { "path": "crates/apm2-daemon/src/htf/AGENTS.md", "scope": "daemon htf module — clock service for time envelope stamping" },
        { "path": "crates/apm2-daemon/src/identity/AGENTS.md", "scope": "daemon identity module — canonical identity identifiers (RFC-0020)" },
        { "path": "crates/apm2-daemon/src/pcac/AGENTS.md", "scope": "daemon pcac module — PCAC lifecycle gate for RequestTool authority" },
        { "path": "crates/apm2-daemon/src/projection/AGENTS.md", "scope": "daemon projection module — write-only projection adapters for external systems" },
        { "path": "crates/apm2-daemon/src/protocol/AGENTS.md", "scope": "daemon protocol module — Unix domain socket protocol stack" },
        { "path": "crates/apm2-daemon/src/session/AGENTS.md", "scope": "daemon session module — episode session management with IPC auth" },
        { "path": "crates/apm2-daemon/src/telemetry/AGENTS.md", "scope": "daemon telemetry module — cgroup-based resource telemetry collection" },
        { "path": "crates/apm2-daemon/src/work/AGENTS.md", "scope": "daemon work module — work lifecycle authority with projection-backed status" },
        { "path": "crates/apm2-holon/AGENTS.md", "scope": "apm2-holon crate — holon framework" },
        { "path": "crates/apm2-holon/src/episode/AGENTS.md", "scope": "holon episode module — bounded episode execution controller" },
        { "path": "crates/apm2-holon/src/ledger/AGENTS.md", "scope": "holon ledger module — append-only hash-chained event log" },
        { "path": "crates/apm2-holon/src/orchestration/AGENTS.md", "scope": "holon orchestration module — FAC revision loop state machine" },
        { "path": "crates/apm2-holon/src/resource/AGENTS.md", "scope": "holon resource module — multi-dimensional budget tracking and lease authorization" },
        { "path": "documents/AGENTS.md", "scope": "documents directory — naming conventions, directory structure" },
        { "path": "documents/theory/AGENTS.md", "scope": "theory documents — unified-theory-v2" },
        { "path": "documents/work/tickets/AGENTS.md", "scope": "work tickets directory — RFC implementation decomposition tickets" }
      ]
    },
    "core_concepts": {
      "context_as_code": {
        "summary": "Compile what you can, discover only what you must.",
        "definition": "Context-as-Code (CAC) is the principle that agent execution contexts are machine-checkable, deterministically reproducible artifacts (not prose or opaque state). Every context is content-addressed, versioned, and bound to specific execution episodes. Agents receive ContextPacks: sealed bundles of (CCP + Budget + Capabilities + Stop-Conditions) that determine exactly what an agent can see and do. This achieves the Zero-Tool Ideal: agents run with zero discovery phase, using only pre-compiled context.",
        "key_principles": [
          "Contexts are artifacts, not environment variables—reproducible and auditable",
          "ContextPacks are content-addressed bundles: one execution = one deterministic context hash",
          "Budget is part of context (tokens, tool-calls, wall-clock)—not a side constraint",
          "Capabilities are explicitly granted; default-deny posture applies",
          "Stop-conditions (goal reached, budget exhausted, blocked, escalated, error) are verifiable facts, not heuristics"
        ],
        "reference_rfc": "RFC-0011"
      },
      "holonic_hierarchy": {
        "summary": "Recursion that scales from one box to 100B agent holarchies.",
        "definition": "Holons are simultaneously wholes (autonomous agents) and parts (components in larger systems). This recursive composition means the same semantics—budgets, capabilities, boundaries, receipts—apply at every scale. A holon has internal structure (sub-holons), a boundary (typed channels), and invariants that compose through recursion depths.",
        "key_principles": [
          "One invariant architecture from single-agent to federated meshes",
          "Boundaries are sealed: Markov blanket prevents data-plane leakage",
          "Communication is typed and canonicalized before hashing/signing",
          "Each recursion level has its own episode, lease, and budget"
        ],
        "reference_rfc": "RFC-0003"
      },
      "ledger_as_truth": {
        "summary": "Truth is append-only; mutable state is derived.",
        "definition": "The Ledger is the Topology of Truth: hash-chained, append-only, monotone. All authoritative facts (work decisions, policy, capability grants, evidence receipts) live in the ledger. Projections (views into the ledger) are disposable caches. Event-sourcing via deterministic reducers derives any mutable workspace state from ledger facts. Scale invariant: one box and global federation both use the same ledger append + reducer pipeline.",
        "key_principles": [
          "No retraction, no hidden state mutation—only appends",
          "Projections are content-addressed and traceable to ledger facts",
          "Reducers are deterministic; same events + reducer = same output",
          "Consensus for control-plane (shared authority facts), convergence for data-plane (CRDTs)"
        ],
        "reference_rfcs": ["RFC-0014", "RFC-0016"]
      },
      "proof_admitted_gates": {
        "summary": "Authority gated by machine-verifiable evidence receipts.",
        "definition": "Every high-impact transition requires a receipt bundle signed by a gate. Gates are policy-indexed closures over evidence facts. Gates enforce the constraint hierarchy: Containment > Correctness > Liveness (S0 > S1 > S2). A fail at higher tiers is monotone—once failed, re-evaluation with more evidence cannot override the failure.",
        "key_principles": [
          "No transition without a gate receipt bound to evidence",
          "Fail dominates verdict aggregation; missing evidence = fail or pending, never pass",
          "High-risk gates (T2/T3) require uncertainty qualification and reverification paths",
          "Tiered policy defines different gates for different risk levels and transition types"
        ],
        "reference_rfcs": ["RFC-0015", "RFC-0019"]
      }
    },
    "major_rfc_context": {
      "purpose": "Fundamental systems every agent must understand when working in this codebase.",
      "last_refreshed_date": "2026-02-11",
      "read_hint": "Before editing runtime, policy, security, or governance code, read the corresponding RFC folder (documents/rfcs/RFC-NNNN/).",
      "rfcs": [
        ["RFC-0001", "APM2 Kernel Architecture: Supervisor, Ledger, Policy, and Syscall Mediation"],
        ["RFC-0003", "Holonic Coordination Framework"],
        ["RFC-0004", "Agent Acceptance Testing (AAT) Implementation"],
        ["RFC-0011", "Context-as-Code (CAC) v1: Canonical Context Pipeline for the APM2 Holonic Kernel"],
        ["RFC-0012", "Agent Coordination Layer for Autonomous Work Loop Execution"],
        ["RFC-0013", "APM2 Kernel Daemon and Holonic Runtime Protocol v1"],
        ["RFC-0014", "Distributed Consensus and Replication Layer for APM2 Ledger+CAS Truth Substrate"],
        ["RFC-0015", "Forge Admission Cycle (FAC) - Hardened Protocol with Cryptographic Gates and OCAP Containment"],
        ["RFC-0016", "Holonic Time Fabric (HTF)"],
        ["RFC-0017", "Daemon as Control Plane: xtask Demotion, Capability-Minted Episodes, Receipt-Backed Orchestration"],
        ["RFC-0018", "Holonic Event Fabric (HEF) Phase 1 - Pulse Plane to Accelerate FAC"],
        ["RFC-0019", "Automated FAC v0: End-to-end ingestion, review episode, durable receipt, GitHub projection"],
        ["RFC-0020", "Holonic Substrate Interface (HSI)"],
        ["RFC-0021", "Venture Proving Holon Interface (VPHI)"],
        ["RFC-0027", "Proof-Carrying Authority Continuity (PCAC)"],
        ["RFC-0028", "Holonic External I/O Security Profile over PCAC"],
        ["RFC-0029", "Holonic External I/O Efficiency Profile over PCAC"]
      ]
    },
    "routing_table": [
      {
        "intent_id": "fac_rolespec",
        "intent_name": "FAC RoleSpec Holder",
        "precondition": "You have a RoleSpec (apm2.role_spec.v1) and a sealed ContextPackManifest from the FAC.",
        "priority_reads": [],
        "supplementary_reads": [],
        "related_skills": [],
        "notes": "This route exists to prevent context pollution. FAC-assigned agents must not load ambient context that could override their scoped permissions or introduce taint."
      },
      {
        "intent_id": "onboarding",
        "intent_name": "First-Time Orientation",
        "precondition": "None.",
        "priority_reads": [
          "README.md",
          "documents/theory/unified-theory-v2.json",
          "crates/apm2-holon/AGENTS.md",
          "documents/AGENTS.md"
        ],
        "supplementary_reads": [
          "DAEMON.md",
          "documents/strategy/ROADMAP.json",
          "SECURITY.md"
        ],
        "related_skills": []
      },
      {
        "intent_id": "coding",
        "intent_name": "Rust Implementation",
        "precondition": "You know which crate(s) and module(s) you are working in.",
        "priority_reads": [
          "README.md",
        ],
        "supplementary_reads": [
          "DAEMON.md",
          "documents/theory/unified-theory-v2.json",
          "proto/kernel_events.proto",
          "proto/apm2d_runtime_v1.proto",
          "proto/tool_protocol.proto"
        ],
        "dynamic_reads": {
          "instruction": "For each crate you touch, read its AGENTS.md. For each module you modify, read its module-level AGENTS.md if it exists.",
          "pattern": "crates/{crate}/AGENTS.md and crates/apm2-core/src/{module}/AGENTS.md"
        },
        "related_skills": [
          "documents/skills/rust-standards/SKILL.md",
          "documents/skills/ticket/SKILL.md"
        ],
        "mandatory_pre_commit": [
          "cargo fmt --all",
          "cargo clippy --workspace --all-targets --all-features -- -D warnings",
          "cargo doc --workspace --no-deps",
          "cargo test --workspace"
        ]
      },
      {
        "intent_id": "testing",
        "intent_name": "Testing and Quality Assurance",
        "precondition": "You know which crate or feature you are testing.",
        "priority_reads": [
          "documents/reviews/AAT_HYPOTHESIS_PROMPT.md",
          "crates/apm2-core/src/evidence/AGENTS.md"
        ],
        "supplementary_reads": [
          "README.md",
          "documents/theory/unified-theory-v2.json"
        ],
        "dynamic_reads": {
          "instruction": "Read the AGENTS.md for the module under test to understand its invariants and contracts.",
          "pattern": "crates/apm2-core/src/{module}/AGENTS.md"
        },
        "related_skills": [
          "documents/skills/aat/SKILL.md",
          "documents/skills/rust-standards/SKILL.md"
        ]
      },
      {
        "intent_id": "security_review",
        "intent_name": "Security Review and Threat Modeling",
        "precondition": "None.",
        "priority_reads": [
          "documents/security/SECURITY_POLICY.cac.json",
          "documents/reviews/SECURITY_REVIEW_PROMPT.md",
          "documents/security/THREAT_MODEL.cac.json",
          "SECURITY.md"
        ],
        "supplementary_reads": [
          "documents/security/SECURITY_POLICY.cac.json",
          "documents/security/INCIDENT_RESPONSE.cac.json",
          "documents/security/NETWORK_DEFENSE.cac.json",
          "documents/security/SECRETS_MANAGEMENT.cac.json",
          "documents/security/SECURITY_CHECKLIST.cac.json",
          "documents/security/consensus-runbook.cac.json"
        ],
        "related_skills": [
          "documents/skills/rust-standards/SKILL.md"
        ]
      },
      {
        "intent_id": "code_review",
        "intent_name": "Code Quality Review",
        "precondition": "You have a PR URL or diff to review.",
        "priority_reads": [
          "documents/reviews/CODE_QUALITY_PROMPT.md",
        ],
        "supplementary_reads": [
          "documents/theory/unified-theory-v2.json",
          "README.md"
        ],
        "dynamic_reads": {
          "instruction": "For each crate touched by the diff, read its AGENTS.md to understand module invariants and contracts.",
          "pattern": "crates/apm2-core/src/{module}/AGENTS.md"
        },
        "related_skills": [
          "documents/skills/rust-standards/SKILL.md"
        ]
      },
      {
        "intent_id": "architecture",
        "intent_name": "Architecture and System Design",
        "precondition": "None.",
        "priority_reads": [
          "documents/theory/unified-theory-v2.json",
          "documents/theory/unified-theory-v2.json"
        ],
        "supplementary_reads": [
          "README.md",
          "DAEMON.md",
          "documents/strategy/ROADMAP.json",
          "documents/strategy/NORTH_STAR.json",
          "documents/strategy/MASTER_STRATEGY.json",
          "crates/apm2-holon/AGENTS.md"
        ],
        "dynamic_reads": {
          "instruction": "Read the RFC(s) most relevant to your design area.",
          "pattern": "documents/rfcs/RFC-{NNNN}/"
        },
        "related_skills": [
          "documents/skills/rfc-council/SKILL.md",
          "documents/skills/idea-compiler/SKILL.md",
          "documents/skills/modes-of-reasoning/SKILL.md"
        ]
      },
      {
        "intent_id": "documentation",
        "intent_name": "Writing Documentation",
        "precondition": "You know which document type you are writing.",
        "priority_reads": [
          "documents/AGENTS.md",
          "documents/theory/unified-theory-v2.json"
        ],
        "supplementary_reads": [
          "README.md",
          "documents/theory/unified-theory-v2.json"
        ],
        "dynamic_reads": {
          "instruction": "Read the template for your document type and at least one existing example.",
          "templates": {
            "prd": "documents/prds/template/",
            "rfc": "documents/rfcs/template/",
            "skill": "documents/skills/skill-authoring/SKILL.md",
            "agents_md": "crates/apm2-core/src/reducer/AGENTS.md",
            "cac_json": "documents/security/SECURITY_POLICY.cac.json"
          }
        },
        "related_skills": [
          "documents/skills/skill-authoring/SKILL.md",
          "documents/skills/prd-review/SKILL.md",
          "documents/skills/rfc-council/SKILL.md",
          "documents/skills/prd-to-rfc/SKILL.md"
        ]
      },
      {
        "intent_id": "research",
        "intent_name": "Research and Exploration",
        "precondition": "None.",
        "priority_reads": [
          "documents/theory/unified-theory-v2.json",
          "README.md"
        ],
        "supplementary_reads": [
          "documents/theory/unified-theory-v2.json",
          "documents/strategy/ROADMAP.json",
          "documents/strategy/BUSINESS_PLAN.json",
          "documents/AGENTS.md"
        ],
        "related_skills": [
          "documents/skills/modes-of-reasoning/SKILL.md"
        ]
      },
      {
        "intent_id": "ci_devops",
        "intent_name": "CI/CD and Infrastructure",
        "precondition": "None.",
        "priority_reads": [
          ".github/workflows/ci.yml"
        ],
        "supplementary_reads": [
          "DAEMON.md",
          ".github/workflows/release.yml",
          ".github/workflows/dev-release.yml",
          ".github/workflows/beta-release.yml",
          ".github/workflows/bench.yml",
          ".github/workflows/miri.yml",
          ".github/workflows/docs.yml",
          "deploy/grafana/",
          "deploy/prometheus/",
          "scripts/"
        ],
        "related_skills": []
      },
      {
        "intent_id": "ticket_execution",
        "intent_name": "Working a Ticket",
        "precondition": "You have a ticket ID (e.g., TCK-00391).",
        "priority_reads": [],
        "supplementary_reads": [
          "README.md",
          "documents/theory/unified-theory-v2.json"
        ],
        "dynamic_reads": {
          "instruction": "Read the ticket YAML, then follow its rfc_id to read the parent RFC, then read the AGENTS.md for every crate/module the ticket touches.",
          "pattern_ticket": "documents/work/tickets/TCK-{NNNNN}.yaml",
          "pattern_rfc": "documents/rfcs/RFC-{NNNN}/",
          "pattern_module": "crates/apm2-core/src/{module}/AGENTS.md"
        },
        "related_skills": [
          "documents/skills/ticket/SKILL.md",
          "documents/skills/rust-standards/SKILL.md",
          "documents/skills/aat/SKILL.md"
        ],
        "mandatory_pre_commit": [
          "cargo fmt --all",
          "cargo clippy --workspace --all-targets --all-features -- -D warnings",
          "cargo doc --workspace --no-deps",
          "cargo test --workspace"
        ]
      },
      {
        "intent_id": "release_management",
        "intent_name": "Release Management",
        "precondition": "None.",
        "priority_reads": [
          "documents/releases/README.md",
          "documents/releases/ARTIFACT_PROMOTION.md",
          "documents/releases/RELEASE_CHANNELS.md",
          "documents/releases/DISTRIBUTION.md"
        ],
        "supplementary_reads": [
          "documents/security/RELEASE_PROCEDURE.cac.json",
          "documents/security/SIGNING_AND_VERIFICATION.cac.json",
          ".github/workflows/release.yml",
          ".github/workflows/dev-release.yml",
          ".github/workflows/beta-release.yml",
          "release-plz.toml",
          "cliff.toml"
        ],
        "related_skills": []
      }
    ]
  }
}
