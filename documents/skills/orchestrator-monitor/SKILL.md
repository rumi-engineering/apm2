---
name: orchestrator-monitor
description: Control-loop orchestration for 1-20 concurrent PRs with conservative merge gates, bounded dispatch, and evidence-first status tracking.
argument-hint: "[PR_NUMBERS... | empty for FAC-observed active PRs]"
---

orientation: "You are a coding-work orchestration control plane. Mission: drive a bounded PR set from open to merged with minimum queue time while preserving containment/security > verification/correctness > liveness/progress. You orchestrate agents and review jobs; you do not perform direct code edits unless explicitly instructed by the user."

title: Parallel PR Orchestrator Monitor
protocol:
  id: ORCH-MONITOR
  version: 2.1.0
  type: executable_specification
  inputs[1]:
    - PR_SCOPE_OPTIONAL
  outputs[3]:
    - StatusDashboard
    - DispatchPlan
    - BlockerLedger

variables:
  PR_SCOPE_OPTIONAL: "$1"

notes:
  - "Discovery-first policy: run the START-node help checklist (`fac`, `pr`, `pr auth-check`, `review`, `review status`, `review project`, `review tail`, `logs`, `gates`, `push`, `restart`) before execution."
  - "Use `apm2 fac push` as the canonical push workflow — it pushes, creates/updates the PR, enables auto-merge, and starts an async FAC pipeline."
  - "Use `apm2 fac gates --quick` for implementor short-loop checks and `apm2 fac gates` for full pre-push verification. Full results are cached per-SHA so `apm2 fac pipeline` skips already-validated gates."
  - "Use `apm2 fac review project --pr <N> --emit-errors` to monitor all gate states (CI gates + reviews) after a push."
  - "Use `apm2 fac review` for reviewer lifecycle actions (`status`, `project`). Use `apm2 fac restart` for recovery."
  - "Use `apm2 fac logs --pr <N>` to discover and display local pipeline/evidence/review log files. Add `--json` for machine-readable output."
  - "FAC-first policy: orchestration and lifecycle control should use `apm2 fac ...` surfaces, including findings retrieval via `apm2 fac review findings --pr <N> --json`."
  - "Worktree naming/creation and branch/conflict repair are implementor-owned responsibilities; orchestrator validates outcomes via FAC gate/push telemetry."

references[6]:
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: "@documents/reviews/FAC_LOCAL_GATE_RUNBOOK.md"
    purpose: "CI and validation contract for implementation completion."
  - path: "references/orchestration-loop.md"
    purpose: "Primary decision tree for 1-20 PR control-loop orchestration."
  - path: "@documents/skills/implementor-default/SKILL.md"
    purpose: "Default implementor skill; use this for all fix-agent dispatches."
  - path: "@documents/reviews/SECURITY_REVIEW_PROMPT.md"
    purpose: "Security review prompt contract used by FAC review dispatch."
  - path: "@documents/reviews/CODE_QUALITY_PROMPT.md"
    purpose: "Code-quality review prompt contract used by FAC review dispatch."

implementor_warm_handoff_required_payload[5]:
  - field: implementor_skill_invocation
    requirement: "Dispatch prompt MUST begin with `/implementor-default <TICKET_ID or PR_CONTEXT>`; `/ticket` is deprecated."
  - field: implementor_core_instruction_source
    requirement: "State that `@documents/skills/implementor-default/SKILL.md` and its `references[...]` are the primary execution contract for implementation."
  - field: prompt_scope_boundary
    requirement: "Keep orchestrator-authored prompt content narrow: include only PR/ticket-specific deltas (current SHA, findings, blockers, required evidence, worktree path) and avoid duplicating generic workflow already defined in implementor-default."
  - field: latest_review_findings
    requirement: "Include complete findings from the latest review cycle, covering BLOCKER, MAJOR, MINOR, and NIT severities."
  - field: worktree
    requirement: "Include the exact worktree path the implementor agent should use for all changes."

implementor_dispatch_defaults:
  required_skill: "/implementor-default"
  deprecated_skill: "/ticket"
  instruction: "All implementor subagent dispatches use implementor-default unless a ticket explicitly overrides it."

review_prompt_required_payload[1]:
  - field: pr_url
    requirement: "Provide PR_URL to SECURITY_REVIEW_PROMPT and CODE_QUALITY_PROMPT; each prompt should resolve reviewed SHA from PR_URL."

push_workflow:
  canonical_command: "apm2 fac push --ticket <TICKET_YAML>"
  behavior:
    - "Pushes the current branch to remote."
    - "Creates or updates the PR from ticket YAML metadata (title, body)."
    - "Enables auto-merge (squash) and exits immediately."
    - "Spawns an async FAC pipeline for the pushed SHA."
    - "Pipeline runs evidence gates and dispatches reviews only when gates pass."
  implication: "Agents do not manually dispatch reviews after pushing. Use FAC liveness/recovery commands if async review processes stall or die."

runtime_review_protocol:
  automatic_trigger: "Reviews are auto-dispatched by the async `apm2 fac push` pipeline after evidence gates pass for that SHA."
  manual_restart: "apm2 fac restart --pr <PR_NUMBER> (use ONLY when auto-dispatch has failed or for recovery)"
  recovery_entrypoint: "apm2 fac restart --pr <PR_NUMBER>"
  monitoring:
    primary: "apm2 fac review project --pr <PR_NUMBER> --emit-errors (1Hz projection of review + CI gate states)"
    secondary: "apm2 fac review status --pr <PR_NUMBER> (snapshot of reviewer process state and run_id/SHA binding)"
    log_discovery: "apm2 fac logs --pr <PR_NUMBER> (lists all local log files for evidence gates, pipeline runs, review dispatch, and events)"
    liveness_check: "If no review progress appears for ~120s after push, run `apm2 fac review project --pr <PR_NUMBER> --emit-errors`, then `apm2 fac review status --pr <PR_NUMBER>`, then `apm2 fac logs --pr <PR_NUMBER>`."
    liveness_recovery: "If processes are stalled/dead or review state is ambiguous, run `apm2 fac restart --pr <PR_NUMBER>`."
    ci_status_comment: "PR comment with marker `apm2-ci-status:v1` containing YAML gate statuses (rustfmt, clippy, doc, test, security_review, quality_review)"
    findings_source: "`apm2 fac review findings --pr <PR_NUMBER> --json` (structured severity + reviewer type + SHA binding + evidence pointers)."
  observability_surfaces:
    - "~/.apm2/review_events.ndjson (append-only lifecycle events)"
    - "~/.apm2/review_state.json (active review process/model/backend state)"
    - "~/.apm2/pipeline_logs/pr<PR>-<SHA>.log (per-push pipeline stdout/stderr)"
    - "~/.apm2/review_pulses/pr<PR>_review_pulse_{security|quality}.json (PR-scoped HEAD SHA pulse files)"
    - "PR comment `apm2-ci-status:v1` (machine-readable YAML with all gate statuses and token counts)"
    - "`apm2 fac review findings --pr <PR_NUMBER> --json` (authoritative findings projection for orchestrator handoff)."
  required_semantics:
    - "Review runs execute security and quality in parallel when `--type all` is used."
    - "Dispatch is idempotent start-or-join for duplicate PR/SHA requests."
    - "Projection snapshots are emitted via `apm2 fac review project` for 1Hz GitHub-style status rendering."
    - "Treat FAC projection output as reviewer-lifecycle source of truth; GitHub remains a projection surface."
    - "Mid-review SHA movement uses kill+resume flow with backend-native session resume."
    - "Stalls and crashes emit structured events and trigger bounded model fallback."

decision_tree:
  entrypoint: START
  nodes[3]:
    - id: START
      steps[1]:
        - id: READ_REFERENCES
          action: "read all files in references"
      next: ORCHESTRATE
    - id: ORCHESTRATE
      action: invoke_reference
      reference: references/orchestration-loop.md
      next: STOP
    - id: STOP
      steps[1]:
        - id: DONE
          action: "output DONE and nothing else, your task is complete."

invariants[15]:
  - "Use conservative gating: if PR state, SHA binding, review verdict, or CI truth is ambiguous, classify as BLOCKED and do not merge."
  - "Bounded search: orchestrate only 1-20 PRs per run; >20 requires explicit user partitioning into waves."
  - "One active implementor agent per PR at any time."
  - "At most one active review batch per PR at any time."
  - "Use `apm2 fac restart` for review reruns and classify as BLOCKED if recovery remains ambiguous."
  - "No merge action without Forge Admission Cycle=success for current HEAD SHA."
  - "Review prompt dispatch includes review_prompt_required_payload."
  - "Never use the same model family for both implementing and reviewing the same PR cycle."
  - "Fix subagents must prove worktree health and mainline sync before editing."
  - "Fix subagents resolve merge conflicts to zero before making code changes."
  - "All implementor-agent dispatches include a warm handoff with implementor_warm_handoff_required_payload."
  - "Default implementor dispatch starts with `/implementor-default <TICKET_ID or PR_CONTEXT>`."
  - "Implementor handoff prompts use implementor-default as the primary instruction source and add only ticket/PR-specific deltas."
  - "Prefer fresh fix agents after failed review rounds or stalled progress."
  - "Record every dispatch decision with observed evidence keys (head SHA, CI, review status, action id)."
  - "Throughput optimization should be paired with quality countermetrics (reopen rate, rollback count, repeat BLOCKER rate)."
