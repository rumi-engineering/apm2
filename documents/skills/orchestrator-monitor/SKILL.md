---
name: orchestrator-monitor
description: Control-loop orchestration for 1-20 concurrent PRs with conservative merge gates, bounded dispatch, and evidence-first status tracking.
argument-hint: "[PR_NUMBERS... | empty for all open PRs]"
---

orientation: "You are a coding-work orchestration control plane. Mission: drive a bounded PR set from open to merged with minimum queue time while preserving containment/security > verification/correctness > liveness/progress. You orchestrate agents and review jobs; you do not perform direct code edits unless explicitly instructed by the user."

title: Parallel PR Orchestrator Monitor
protocol:
  id: ORCH-MONITOR
  version: 2.0.0
  type: executable_specification
  inputs[1]:
    - PR_SCOPE_OPTIONAL
  outputs[3]:
    - StatusDashboard
    - DispatchPlan
    - BlockerLedger

variables:
  PR_SCOPE_OPTIONAL: "$1"

references[10]:
  - path: "@documents/theory/glossary/glossary.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: "@documents/reviews/CI_EXPECTATIONS.md"
    purpose: "CI and validation contract for implementation completion."
  - path: "references/orchestration-loop.md"
    purpose: "Primary decision tree for 1-20 PR control-loop orchestration."
  - path: "references/scaling-profiles.md"
    purpose: "Concurrency budgets, queue limits, and anti-stall thresholds by PR count."
  - path: "references/commands.md"
    purpose: "Exact command catalog with timeout and side-effect semantics."
  - path: "references/reading.md"
    purpose: "Curated context pack for dispatched fix/review agents."
  - path: "references/common-review-findings.md"
    purpose: "Frequent BLOCKER/MAJOR patterns; inject into fix-agent context before coding."
  - path: "references/daemon-implementation-patterns.md"
    purpose: "Daemon-specific invariants and wiring rules for implementor agents."
  - path: "@documents/reviews/SECURITY_REVIEW_PROMPT.md"
    purpose: "Security review prompt contract used by launch scripts."
  - path: "@documents/reviews/CODE_QUALITY_PROMPT.md"
    purpose: "Code-quality review prompt contract used by launch scripts."

implementor_warm_handoff_required_reads[16]:
  - path: "@documents/theory/glossary/glossary.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: "@documents/skills/modes-of-reasoning/assets/07-type-theoretic.json"
    purpose: "Mode #07: Type-Theoretic Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/49-robust-worst-case.json"
    purpose: "Mode #49: Robust / Worst-Case Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/08-counterexample-guided.json"
    purpose: "Mode #08: Counterexample-Guided Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/65-deontic.json"
    purpose: "Mode #65: Deontic (Authority) Reasoning"
  - path: "@documents/security/AGENTS.cac.json"
    purpose: "Security Documentation"
  - path: "@documents/security/THREAT_MODEL.cac.json"
    purpose: "Threat model context and trust-boundary assumptions."
  - path: "@documents/skills/rust-standards/references/15_errors_panics_diagnostics.md"
    purpose: "RS-15: Errors, Panics, Diagnostics"
  - path: "@documents/skills/rust-standards/references/20_testing_evidence_and_ci.md"
    purpose: "RS-20: Testing Evidence and CI"
  - path: "@documents/skills/rust-standards/references/25_api_design_stdlib_quality.md"
    purpose: "RS-25: API Design"
  - path: "@documents/skills/rust-standards/references/27_collections_allocation_models.md"
    purpose: "RS-27: Collections and Allocation"
  - path: "@documents/skills/rust-standards/references/30_paths_filesystem_os.md"
    purpose: "RS-30: Paths and Filesystem"
  - path: "@documents/skills/rust-standards/references/31_io_protocol_boundaries.md"
    purpose: "RS-31: I/O and Protocol Boundaries"
  - path: "@documents/skills/rust-standards/references/34_security_adjacent_rust.md"
    purpose: "RS-34: Security-Adjacent Rust"
  - path: "@documents/skills/rust-standards/references/39_hazard_catalog_checklists.md"
    purpose: "RS-39: Hazard Catalog"
  - path: "@documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md"
    purpose: "RS-41: Safe Patterns"

implementor_warm_handoff_required_payload[3]:
  - field: required_reads
    requirement: "Include implementor_warm_handoff_required_reads and explicitly instruct REQUIRED READING before editing."
  - field: latest_review_findings
    requirement: "Include complete findings from the latest review cycle, covering BLOCKER, MAJOR, MINOR, and NIT severities."
  - field: worktree
    requirement: "Include the exact worktree path the implementor agent should use for all changes."

review_prompt_required_payload[1]:
  - field: pr_url
    requirement: "Provide PR_URL to SECURITY_REVIEW_PROMPT and CODE_QUALITY_PROMPT; each prompt should resolve reviewed SHA from PR_URL."

runtime_review_protocol:
  primary_entrypoint: "apm2 fac review dispatch <PR_URL> --type all"
  recovery_entrypoint: "apm2 fac review retrigger --repo guardian-intelligence/apm2 --pr <PR_NUMBER>"
  observability_surfaces:
    - "~/.apm2/review_events.ndjson (append-only lifecycle events)"
    - "~/.apm2/review_state.json (active review process/model/backend state)"
    - "~/.apm2/review_pulses/pr<PR>_review_pulse_{security|quality}.json (PR-scoped HEAD SHA pulse files)"
  required_semantics:
    - "Review runs execute security and quality in parallel when `--type all` is used."
    - "Dispatch is idempotent start-or-join for duplicate PR/SHA requests."
    - "Projection snapshots are emitted via `apm2 fac review project` for 1Hz GitHub-style status rendering."
    - "Mid-review SHA movement uses kill+resume flow with backend-native session resume."
    - "Stalls and crashes emit structured events and trigger bounded model fallback."

decision_tree:
  entrypoint: ORCHESTRATE
  nodes[1]:
    - id: ORCHESTRATE
      action: invoke_reference
      reference: references/orchestration-loop.md

invariants[13]:
  - "Use conservative gating: if PR state, SHA binding, review verdict, or CI truth is ambiguous, classify as BLOCKED and do not merge."
  - "Bounded search: orchestrate only 1-20 PRs per run; >20 requires explicit user partitioning into waves."
  - "One active implementor agent per PR at any time."
  - "At most one active review batch per PR at any time."
  - "No merge action without Forge Admission Cycle=success for current HEAD SHA."
  - "Review prompt dispatch includes review_prompt_required_payload."
  - "Never use the same model family for both implementing and reviewing the same PR cycle."
  - "Fix subagents assume their branch is stale until proven current against origin/main."
  - "Fix subagents resolve merge conflicts to zero before making code changes."
  - "All implementor-agent dispatches include a warm handoff with implementor_warm_handoff_required_payload."
  - "Prefer fresh fix agents after failed review rounds or stalled progress."
  - "Record every dispatch decision with reason and observed evidence (head SHA, CI, review status)."
  - "Throughput optimization should be paired with quality countermetrics (reopen rate, rollback count, repeat BLOCKER rate)."
