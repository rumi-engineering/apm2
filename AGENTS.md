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
        { "path": "documents/AGENTS.md", "scope": "documents directory — naming conventions, directory structure" },
        { "path": "documents/theory/AGENTS.md", "scope": "theory documents — unified-theory-v2" },
        { "path": "crates/apm2-cli/AGENTS.md", "scope": "apm2-cli crate" },
        { "path": "crates/apm2-daemon/AGENTS.md", "scope": "apm2-daemon crate" },
        { "path": "crates/apm2-holon/AGENTS.md", "scope": "apm2-holon crate — holon framework" },
        { "path": "crates/apm2-core/src/adapter/AGENTS.md", "scope": "adapter module" },
        { "path": "crates/apm2-core/src/agent/AGENTS.md", "scope": "agent module" },
        { "path": "crates/apm2-core/src/bootstrap/AGENTS.md", "scope": "bootstrap module" },
        { "path": "crates/apm2-core/src/budget/AGENTS.md", "scope": "budget module" },
        { "path": "crates/apm2-core/src/cac/AGENTS.md", "scope": "cac module" },
        { "path": "crates/apm2-core/src/config/AGENTS.md", "scope": "config module" },
        { "path": "crates/apm2-core/src/consensus/AGENTS.md", "scope": "consensus module" },
        { "path": "crates/apm2-core/src/credentials/AGENTS.md", "scope": "credentials module" },
        { "path": "crates/apm2-core/src/crypto/AGENTS.md", "scope": "crypto module" },
        { "path": "crates/apm2-core/src/determinism/AGENTS.md", "scope": "determinism module" },
        { "path": "crates/apm2-core/src/events/AGENTS.md", "scope": "events module" },
        { "path": "crates/apm2-core/src/evidence/AGENTS.md", "scope": "evidence module" },
        { "path": "crates/apm2-core/src/github/AGENTS.md", "scope": "github module" },
        { "path": "crates/apm2-core/src/health/AGENTS.md", "scope": "health module" },
        { "path": "crates/apm2-core/src/impact_map/AGENTS.md", "scope": "impact_map module" },
        { "path": "crates/apm2-core/src/lease/AGENTS.md", "scope": "lease module" },
        { "path": "crates/apm2-core/src/ledger/AGENTS.md", "scope": "ledger module" },
        { "path": "crates/apm2-core/src/log/AGENTS.md", "scope": "log module" },
        { "path": "crates/apm2-core/src/process/AGENTS.md", "scope": "process module" },
        { "path": "crates/apm2-core/src/reducer/AGENTS.md", "scope": "reducer module" },
        { "path": "crates/apm2-core/src/restart/AGENTS.md", "scope": "restart module" },
        { "path": "crates/apm2-core/src/schema_registry/AGENTS.md", "scope": "schema_registry module" },
        { "path": "crates/apm2-core/src/session/AGENTS.md", "scope": "session module" },
        { "path": "crates/apm2-core/src/shutdown/AGENTS.md", "scope": "shutdown module" },
        { "path": "crates/apm2-core/src/state/AGENTS.md", "scope": "state module" },
        { "path": "crates/apm2-core/src/supervisor/AGENTS.md", "scope": "supervisor module" },
        { "path": "crates/apm2-core/src/tool/AGENTS.md", "scope": "tool module" },
        { "path": "crates/apm2-core/src/webhook/AGENTS.md", "scope": "webhook module" },
        { "path": "crates/apm2-core/src/work/AGENTS.md", "scope": "work module" }
      ]
    },
    "major_rfc_context": {
      "purpose": "High-signal index of major, recent system work so agents can pick the right RFC context quickly.",
      "selection_policy": {
        "implemented_definition": "RFC status == APPROVED in documents/rfcs/RFC-*/00_meta.yaml",
        "recent_window_start": "2026-01-24",
        "last_refreshed_date": "2026-02-06",
        "fail_closed_rule": "If RFC status is missing or ambiguous, exclude it from recent_implemented."
      },
      "schema": "[Major_System, RFC_ids]",
      "recent_implemented": [
        ["Automated Forge Admission Cycle (FAC)", ["RFC-0019"]],
        ["Holonic Event Fabric (HEF) Pulse Plane", ["RFC-0018"]],
        ["Holonic Time Fabric (HTF)", ["RFC-0016"]],
        ["Daemon Control Plane", ["RFC-0017"]],
        ["Context-as-Code (CAC) Pipeline", ["RFC-0011"]],
        ["Distributed Consensus + Replication Substrate", ["RFC-0014"]],
        ["Agent Coordination Layer", ["RFC-0012"]],
        ["Agent Acceptance Testing (AAT)", ["RFC-0004"]]
      ],
      "major_in_flight": [
        ["Forge Admission Cycle (FAC) Gate Hardening Basis", ["RFC-0015"]],
        ["Holonic Substrate Interface (HSI)", ["RFC-0020"]],
        ["Venture Proving Holon Interface (VPHI)", ["RFC-0021"]]
      ],
      "read_hint": "If your task intersects a listed system, read its RFC folder before editing runtime, policy, security, or governance surfaces."
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
          "documents/reviews/CI_EXPECTATIONS.md"
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
          "documents/reviews/CI_EXPECTATIONS.md",
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
          "documents/security/AGENTS.cac.json",
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
          "documents/reviews/CI_EXPECTATIONS.md"
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
            "cac_json": "documents/security/AGENTS.cac.json"
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
          "documents/reviews/CI_EXPECTATIONS.md",
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
        "priority_reads": [
          "documents/reviews/CI_EXPECTATIONS.md"
        ],
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
