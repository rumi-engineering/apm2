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
  - "Use `apm2 fac push` as the canonical push workflow — it pushes, creates/updates the PR, enables auto-merge, and starts an async FAC pipeline."
  - "Use `apm2 fac gates --quick` for implementor short-loop checks and `apm2 fac gates` for full pre-push verification. Full results are cached per-SHA so `apm2 fac pipeline` skips already-validated gates."
  - "Use `apm2 fac review status --pr <N> --json` as the primary reviewer lifecycle signal (run_id, lane state, head SHA binding, terminal_reason)."
  - "Use lane-scoped status checks for control actions: `apm2 fac review status --pr <N> --type security --json` and `apm2 fac review status --pr <N> --type quality --json`."
  - "Use `apm2 fac logs --pr <N> --json` as the canonical per-PR log discovery command, then `tail -f` the returned review/pipeline log paths for up-to-date execution output."
  - "FAC-first policy: orchestration and lifecycle control should use `apm2 fac ...` surfaces, including findings retrieval via `apm2 fac review findings --pr <N> --json`."
  - "Worktree naming/creation and branch/conflict repair are implementor-owned responsibilities; orchestrator validates outcomes via FAC gate/push telemetry."

references[4]:
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: "@documents/skills/implementor-default/SKILL.md"
    purpose: "Default implementor skill; use this for all fix-agent dispatches."

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
  instruction: "All implementor subagent dispatches use implementor-default unless a ticket explicitly overrides it."

review_prompt_required_payload[1]:
  - field: pr_number
    requirement: "Provide PR_NUMBER context to SECURITY_REVIEW_PROMPT and CODE_QUALITY_PROMPT; each prompt resolves reviewed SHA from local FAC prepare/status surfaces."

push_workflow:
  canonical_command: "apm2 fac push --ticket <TICKET_YAML>"
  CRITICAL_PREREQUISITE: |
    ALL changes MUST be committed before running `apm2 fac gates` or `apm2 fac push`.
    These commands WILL FAIL on a dirty working tree. Build artifacts are attested
    against the committed HEAD SHA and reused as a source of truth — uncommitted
    changes produce unattestable results. Ensure implementor agents commit everything
    (including docs, tickets, and config) before invoking gates or push.
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
    primary: "apm2 fac review status --pr <PR_NUMBER> --json (authoritative reviewer lifecycle snapshot: security/quality state, run_id, sequence, terminal_reason, SHA binding)"
    lane_health: "apm2 fac review status --pr <PR_NUMBER> --type <security|quality> --json (best lane-level signal for kill/revive decisions)"
    log_discovery: "apm2 fac logs --pr <PR_NUMBER> --json (canonical per-PR log path inventory for evidence gates, pipeline, and review runs)"
    live_logs: "Use `tail -f` on paths returned by `apm2 fac logs --pr <PR_NUMBER> --json` to monitor live reviewer output."
    liveness_check: "If no review progress appears for ~120s after push, run lane-scoped status for both lanes, then refresh log paths with `apm2 fac logs --pr <PR_NUMBER> --json` and tail the active run logs."
    liveness_recovery: "If a single reviewer lane is stuck, terminate it with `apm2 fac review terminate --pr <PR_NUMBER> --type <security|quality> --json` then restart with `apm2 fac restart --pr <PR_NUMBER>`. If both lanes or the full pipeline are stuck, run `apm2 fac restart --pr <PR_NUMBER>` directly."
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
    - "Treat `apm2 fac review status` + per-PR logs from `apm2 fac logs --pr <PR_NUMBER>` as the reviewer-lifecycle source of truth; GitHub remains a projection surface."
    - "Mid-review SHA movement uses kill+resume flow with backend-native session resume."
    - "Stalls and crashes emit structured events and trigger bounded model fallback."

decision_tree:
  entrypoint: START
  nodes[9]:
    - id: START
      purpose: "Initialize scope and verify prerequisites before any side effects."
      steps[6]:
        - id: READ_REQUIRED_REFERENCES
          action: |
            Read all required references in order:
            (1) @documents/theory/unified-theory-v2.json (REQUIRED: APM2 terminology and ontology)
            (2) @documents/skills/implementor-default/SKILL.md (default implementor skill for all fix-agent dispatches)
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <...> placeholders with concrete values."
        - id: DISCOVER_RELEVANT_FAC_HELP
          action: |
            Discovery phase is mandatory. Run this exact help checklist before command execution:
            (1) `apm2 fac --help`
            (2) `apm2 fac pr --help`
            (3) `apm2 fac pr auth-check --help`
            (4) `apm2 fac review --help`
            (5) `apm2 fac review status --help`
            (6) `apm2 fac review findings --help`
            (7) `apm2 fac review tail --help`
            (8) `apm2 fac review verdict --help`
            (9) `apm2 fac review verdict set --help`
            (10) `apm2 fac logs --help`
            (11) `apm2 fac gates --help`
            (12) `apm2 fac push --help`
            (13) `apm2 fac restart --help`
            (14) `apm2 fac review terminate --help`
        - id: VERIFY_REPO_AUTH
          action: "Run `apm2 fac pr auth-check`."
        - id: RESOLVE_PR_SCOPE
          action: "If explicit PR numbers were provided, use them. Otherwise run fac_review_status (global) and infer active PR scope from FAC review entries/recent events."
        - id: ENFORCE_SCOPE_BOUND
          action: "If scoped open PR count >20, pause and request wave partitioning."
      next: HEARTBEAT_LOOP

    - id: HEARTBEAT_LOOP
      purpose: "Run bounded, evidence-first orchestration ticks until stop condition."
      steps[5]:
        - id: SNAPSHOT
          action: "Capture per-PR fac_review_status (including lane-scoped status) as the primary lifecycle signal; use fac_logs and fac_review_tail for diagnosis context."
        - id: COLLECT_FINDINGS_FROM_FAC
          action: |
            For each PR, fetch structured findings via FAC:
            `apm2 fac review findings --pr <PR_NUMBER> --json`
            Use this output as the source for BLOCKER/MAJOR/MINOR/NIT findings in implementor handoff.
        - id: CLASSIFY
          action: |
            For each PR, assign exactly one state:
            MERGED | READY_TO_MERGE | PR_CONFLICTING | CI_FAILED | REVIEW_FAILED |
            REVIEW_MISSING | WAITING_CI | BLOCKED_UNKNOWN.
        - id: APPLY_FAIL_CLOSED_GATES
          action: |
            If state cannot be determined exactly, or review statuses are not bound to current HEAD SHA,
            classify as BLOCKED_UNKNOWN and defer merge action.
        - id: PLAN_DISPATCH
          action: |
            Create this tick's action list using fixed orchestration bounds:
            (1) never more than 3 total actions per tick,
            (2) never more than 1 action for a single PR per tick,
            (3) at most 1 implementor dispatch and at most 1 restart action per tick.
            Prioritize states in this order:
            READY_TO_MERGE, PR_CONFLICTING, CI_FAILED, REVIEW_FAILED, REVIEW_MISSING, WAITING_CI, BLOCKED_UNKNOWN.
      next: EXECUTE_ACTIONS

    - id: EXECUTE_ACTIONS
      purpose: "Apply bounded actions while preventing duplicate workers per PR."
      steps[6]:
        - id: READY_TO_MERGE_ACTION
          action: "For READY_TO_MERGE PRs, keep monitoring. `apm2 fac push` already enables auto-merge on each implementor push."
        - id: REVIEW_MONITOR_ACTION
          action: |
            For REVIEW_MISSING PRs: reviews auto-start via the Forge Admission Cycle CI workflow on push.
            Do NOT manually dispatch reviews. Instead, monitor with lane-scoped
            `apm2 fac review status --pr <N> --type <security|quality> --json`
            and per-PR logs from `apm2 fac logs --pr <N> --json`.
            If reviews have not started within 2 minutes of the push, use `apm2 fac restart --pr <PR_NUMBER>` as recovery.
        - id: FIX_AGENT_ACTION
          action: |
            For CI_FAILED, REVIEW_FAILED, or PR_CONFLICTING PRs with implementor slots, dispatch one fresh fix agent
            with `/implementor-default <TICKET_ID or PR_CONTEXT>`.
            Inject @documents/skills/implementor-default/SKILL.md in its context.
            Fix agents should use `apm2 fac push` to push their changes — this auto-creates/updates the PR and triggers reviews.
        - id: REVIEW_PROGRESS_ACTION
          action: "For PRs with active reviews, run fac_review_status (both lane-scoped and aggregate) and refresh/tail per-PR logs from fac_logs; the Forge Admission Cycle workflow remains the GitHub projection path."
        - id: NO_DUPLICATE_OWNERSHIP
          action: "Never run two implementor agents or two review batches for the same PR in the same tick."
      next: STALL_AND_BACKPRESSURE

    - id: STALL_AND_BACKPRESSURE
      purpose: "Contain fanout and recover from stalled workers."
      steps[4]:
        - id: ENFORCE_BACKPRESSURE
          action: |
            Apply queue guards before adding actions:
            (1) if review backlog is high or review processes are saturated, skip net-new implementor dispatches for this tick,
            (2) if CI failure ratio spikes over the last 3 ticks, dispatch fixes only and avoid net-new work,
            (3) if a review for the current SHA is already active, do not restart it.
        - id: STALE_SHA_RECOVERY
          action: "If HEAD changed after review launch, mark old review stale and requeue on new HEAD."
        - id: IDLE_AGENT_RECOVERY
          action: "If an implementor has no progress signal for >=120 seconds, replace with a fresh agent."
        - id: SATURATION_CHECK
          action: "Use fac_review_status (global) to ensure active FAC review runs remain within bounded capacity before any restart/dispatch action."
      next: SYNC_TICK_FACTS

    - id: SYNC_TICK_FACTS
      purpose: "Sync machine-verifiable orchestration facts."
      steps[3]:
        - id: SYNC_PR_STATE_FACTS
          action: "Persist current PR states and gate states in FAC projections/log artifacts."
        - id: SYNC_ACTION_FACTS
          action: "Persist executed/skipped action facts keyed by PR, SHA, and scheduler slot."
        - id: SYNC_BLOCKER_FACTS
          action: "Persist BLOCKED_UNKNOWN facts with evidence selectors required for unblock."
      next: STOP_OR_CONTINUE

    - id: STOP_OR_CONTINUE
      purpose: "Terminate only on explicit terminal conditions."
      decisions[3]:
        - id: SUCCESS_STOP
          if: "all scoped PRs are MERGED"
          then:
            next: STOP

        - id: PARTIAL_STOP
          if: "all remaining PRs are BLOCKED_UNKNOWN for >=3 consecutive ticks"
          then:
            next: STOP

        - id: CONTINUE
          if: "otherwise"
          then:
            next: HEARTBEAT_LOOP

    - id: FIX_AGENT_PROMPT_CONTRACT
      purpose: "Ensure implementor agent briefs are consistent and conservatively gated."
      steps[9]:
        - id: REQUIRE_DEFAULT_IMPLEMENTOR_SKILL
          action: "Prompt must start with `/implementor-default <TICKET_ID or PR_CONTEXT>`."
        - id: REQUIRE_FINDINGS_SOURCE
          action: "Build explicit findings list from `apm2 fac review findings --pr <PR_NUMBER> --json` output and include it in handoff."
        - id: INCLUDE_REQUIRED_CONTEXT
          action: |
            Include PR number, branch, HEAD SHA, explicit findings list, and required reference:
            @documents/skills/implementor-default/SKILL.md.
        - id: REQUIRE_BRANCH_SYNC_BEFORE_EDIT
          action: |
            Require implementor-owned worktree health loop before any code edits:
            (1) choose/create the intended worktree path,
            (2) synchronize branch ancestry with current mainline policy,
            (3) reduce merge-conflict count to zero,
            (4) proceed only when worktree is conflict-free.
        - id: REQUIRE_CONFLICT_EVIDENCE
          action: |
            Require branch hygiene facts to be verifiable from FAC artifacts:
            worktree path, base commit before sync, base commit after sync, conflict file list (or explicit 'none').
        - id: ENFORCE_BRANCH_HYGIENE_GATE
          action: |
            If branch sync facts are missing from artifacts or unresolved conflicts remain,
            redispatch a fresh fix subagent.
        - id: REQUIRE_PRE_COMMIT_ORDER
          action: |
            During active edits, run `apm2 fac gates --quick` for short-loop validation.
            Immediately before push, run `apm2 fac gates` and preserve per-gate outcomes in FAC artifacts.
        - id: REQUIRE_FAC_PUSH
          action: "Push only via `apm2 fac push` (`--ticket` preferred, `--branch` fallback)."
        - id: REQUIRE_EVIDENCE
          action: "Require exact command and diff facts in artifacts; do not rely on narrative explanations."
      next: HEARTBEAT_LOOP

    - id: REVIEW_GATE_DEFINITION
      purpose: "Define merge readiness in machine terms."
      steps[1]:
        - id: GATE_RULE
          action: |
            READY_TO_MERGE iff all are true on current HEAD SHA:
            (1) `apm2 fac review status --pr <PR_NUMBER> --type security --json` reports terminal non-failed state bound to current head SHA,
            (2) `apm2 fac review status --pr <PR_NUMBER> --type quality --json` reports terminal non-failed state bound to current head SHA,
            (3) `apm2 fac review findings --pr <PR_NUMBER> --json` reports non-fail-closed, non-ERROR findings for current head SHA.
      next: HEARTBEAT_LOOP

    - id: STOP
      purpose: "Terminate."
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
