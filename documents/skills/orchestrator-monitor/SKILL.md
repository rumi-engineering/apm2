---
name: orchestrator-monitor
description: Control-loop orchestration for 1-20 concurrent PRs with conservative merge gates, bounded dispatch, and evidence-first status tracking.
argument-hint: "[PR_NUMBERS... | empty for FAC-observed active PRs]"
---

orientation: "You are managing the Forge Admission Cycle for one or more merge requests. The local VPS and the repository you are operating within are the source of truth. The main branch of ~/Projects/apm2 must be kept pristine. GitHub is merely one projection of this Forge — do not treat it as authoritative. Your role is to ensure the Forge Admission Cycle proceeds to completion despite any errors in operation. You orchestrate implementor agents and review jobs; you do not perform direct code edits. Priority order: containment/security > verification/correctness > liveness/progress."

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
  - "Use `apm2 fac doctor --pr <N> --json` as the primary reviewer lifecycle signal (run_id, lane state, head SHA binding, terminal_reason)."
  - "Use lane-scoped status checks for control actions: `apm2 fac doctor --pr <N> --json` for lifecycle state, `apm2 fac logs --pr <N> --json` for log discovery."
  - "Use `apm2 fac logs --pr <N> --json` as the canonical per-PR log discovery command, then `tail -f` the returned review/pipeline log paths for up-to-date execution output."
  - "Use `apm2 fac doctor --pr <N> --json` as the single per-PR source of findings_summary, merge_readiness, agents, and recommended_action."
  - "Worktree naming/creation and branch/conflict repair are implementor-owned responsibilities; orchestrator validates outcomes via FAC gate/push telemetry."

references[1]:
  - path: "@documents/skills/implementor-default/SKILL.md"
    purpose: "Default implementor skill; use this for all fix-agent dispatches."

implementor_warm_handoff_required_payload[5]:
  - field: implementor_skill_invocation
    requirement: "Dispatch prompt MUST begin with `/implementor-default <TICKET_ID or PR_CONTEXT>`; `/ticket` is deprecated."
  - field: implementor_core_instruction_source
    requirement: "State that `@documents/skills/implementor-default/SKILL.md` are the primary execution contract for implementation."
  - field: prompt_scope_boundary
    requirement: "Keep orchestrator-authored prompt content narrow: include only PR/ticket-specific deltas (current SHA, findings, blockers, required evidence, worktree path) and avoid duplicating generic workflow already defined in implementor-default."
  - field: latest_review_findings
    requirement: "Include complete findings from the latest review cycle, covering BLOCKER, MAJOR, MINOR, and NIT severities."
  - field: worktree
    requirement: "Include the exact worktree path the implementor agent should use for all changes."

implementor_dispatch_defaults:
  required_skill: "/implementor-default"
  instruction: "All implementor subagent dispatches use implementor-default unless a ticket explicitly overrides it."

decision_tree:
  entrypoint: START
  nodes[8]:
    - id: START
      purpose: "Initialize scope and verify prerequisites before any side effects."
      steps[5]:
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
            (4) `apm2 fac doctor --help`
            (5) `apm2 fac review findings --help`
        - id: RESOLVE_PR_SCOPE
          action: "If explicit PR numbers were provided, use them. Otherwise run `apm2 fac doctor --json` (no --pr filter) to discover all tracked PRs from FAC review entries/recent events. This global view is for PR discovery ONLY — capacity enforcement is always per-PR."
        - id: ENFORCE_SCOPE_BOUND
          action: "If scoped open PR count >20, pause and request wave partitioning."
      next: HEARTBEAT_LOOP

    - id: HEARTBEAT_LOOP
      purpose: "Run bounded, evidence-first orchestration ticks until stop condition."
      steps[4]:
        - id: SNAPSHOT
          action: "Capture per-PR `apm2 fac doctor --pr <N> --json` snapshots as the primary lifecycle signal; use fac_logs and fac_review_tail for diagnosis context."
        - id: COLLECT_FINDINGS_FROM_FAC
          action: |
            For each PR, use `apm2 fac doctor --pr <PR_NUMBER> --json` and read
            `findings_summary` as the source of BLOCKER/MAJOR/MINOR/NIT counts
            and formal/computed verdict state for implementor handoff.
        - id: CLASSIFY
          action: |
            For each PR, assign exactly one state:
            MERGED | READY_TO_MERGE | PR_CONFLICTING | CI_FAILED | REVIEW_FAILED |
            REVIEW_MISSING | WAITING_CI | BLOCKED_UNKNOWN.
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
      steps[5]:
        - id: READY_TO_MERGE_ACTION
          action: "For READY_TO_MERGE PRs, check main branch and check if the commit was merged, if not, check again shortly until the commit is merged.
        - id: REVIEW_MONITOR_ACTION
          action: |
            For REVIEW_MISSING PRs: reviews auto-start via the Forge Admission Cycle CI workflow on push.
            Do NOT manually dispatch reviews. Instead, monitor with `apm2 fac doctor --pr <N> --json`
        - id: FIX_AGENT_ACTION
          action: |
            For CI_FAILED, REVIEW_FAILED, or PR_CONFLICTING PRs with implementor slots, dispatch one fresh fix agent
            with `/implementor-default <TICKET_ID or PR_CONTEXT>`.
            Inject @documents/skills/implementor-default/SKILL.md in its context.
            Fix agents should use `apm2 fac push` to push their changes — this auto-creates/updates the PR and triggers reviews.
        - id: REVIEW_PROGRESS_ACTION
          action: "For PRs with active reviews, run `apm2 fac doctor --pr <N> --json` (per-PR, both lane-scoped and aggregate) and refresh/tail per-PR logs from fac_logs."
        - id: NO_DUPLICATE_OWNERSHIP
          action: "Never run two implementor agents or two review batches for the same PR in the same tick."
      next: STALL_AND_BACKPRESSURE

    - id: STALL_AND_BACKPRESSURE
      purpose: "Contain fanout and recover from stalled workers."
      steps[3]:
        - id: ENFORCE_BACKPRESSURE
          action: |
            Apply per-PR queue guards before adding actions:
            (1) if a specific PR's review agents are at capacity (check via `apm2 fac doctor --pr <N> --json`), skip net-new implementor dispatches for that PR this tick,
            (2) if a review for the current SHA is already active on a given PR, do not restart it.
            Note: backpressure is always scoped per-PR — a saturated PR does not block dispatch for other PRs.
        - id: IDLE_AGENT_RECOVERY
          action: "If an implementor has no progress signal for >=180 seconds, replace with a fresh agent."
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
      steps[8]:
        - id: REQUIRE_DEFAULT_IMPLEMENTOR_SKILL
          action: "Prompt must start with `/implementor-default <TICKET_ID or PR_CONTEXT>`."
        - id: REQUIRE_FINDINGS_SOURCE
          action: "Build findings handoff from `apm2 fac doctor --pr <PR_NUMBER> --json` (`findings_summary` + recommendation reason) and include it in the implementor prompt."
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
            (1) `apm2 fac doctor --pr <PR_NUMBER> --json` reports `merge_readiness.all_verdicts_approve=true`,
            (2) `apm2 fac doctor --pr <PR_NUMBER> --json` reports `merge_readiness.gates_pass=true`,
            (3) `apm2 fac doctor --pr <PR_NUMBER> --json` reports `merge_readiness.sha_fresh=true` and `merge_readiness.no_merge_conflicts=true`.
      next: HEARTBEAT_LOOP

    - id: STOP
      purpose: "Terminate."
      steps[1]:
        - id: DONE
          action: "output DONE and nothing else, your task is complete."

operational_playbook:
  purpose: "Action table keyed to FAC CLI observations. Use this to decide what to do next."
  scenarios[12]:
    - trigger: "Doctor reports deny with actionable findings"
      observed_via: "`apm2 fac doctor --pr <N> --json` shows `recommended_action.action=dispatch_implementor` and findings_summary blocker/major > 0"
      action: "Dispatch a fresh implementor agent with `/implementor-default` including the full findings list in the handoff. Do not reuse a stalled agent."

    - trigger: "Only MINOR/NIT findings present"
      observed_via: "`apm2 fac doctor --pr <N> --json` findings_summary shows blocker=0 and major=0"
      action: "Do not manually set verdicts. Continue monitoring doctor until merge_readiness becomes true or a new recommendation is emitted."

    - trigger: "Review posted with PASS verdict and no findings"
      observed_via: "`apm2 fac doctor --pr <N> --json` shows state=done, terminal_reason=pass for both lanes"
      action: "PR is READY_TO_MERGE. Verify main branch has the PR merged in and only proceed to the next ticket once"

    - trigger: "Implementor agent pushed a new commit"
      observed_via: "Agent reports `apm2 fac push` completed, or head SHA changed in `apm2 fac doctor --pr <N> --json`"
      action: "Monitor review dispatch. Reviews auto-start via CI workflow on push. Check lane status after ~2 minutes. If reviews have not started, use `apm2 fac restart --pr <N>`."

    - trigger: "Review lane shows state=alive"
      observed_via: "`apm2 fac doctor --pr <N> --json` reports active reviewer agents and recommended_action=wait"
      action: "Review is in progress. Monitor with `apm2 fac review tail --pr <N> --type <security|quality>` or tail the log file from `apm2 fac logs --pr <N> --json`. Do not restart or dispatch."

    - trigger: "No active reviewers and verdict pending"
      observed_via: "`apm2 fac doctor --pr <N> --json` reports `recommended_action.action=restart_reviews`"
      action: "Run the exact command in `recommended_action.command` (normally `apm2 fac restart --pr <N> --refresh-identity`)."

    - trigger: "Integrity/corruption health signal"
      observed_via: "`apm2 fac doctor --pr <N> --json` reports `recommended_action.action=fix`"
      action: "Run `apm2 fac doctor --pr <N> --fix`. Do not manually delete state files."

    - trigger: "Review lane shows failed/crashed terminal state"
      observed_via: "`apm2 fac doctor --pr <N> --json` reports failed/crashed lanes or `recommended_action.action=restart_reviews`"
      action: "Follow `recommended_action.command`; use `apm2 fac logs --pr <N> --json` only for diagnosis context."

    - trigger: "Evidence gates failed during push"
      observed_via: "`apm2 fac push` exits with error mentioning failing gates (rustfmt, clippy, test, etc.)"
      action: "Implementor must fix the failing gate. Use `apm2 fac gates --quick` for fast iteration, then `apm2 fac gates` for full validation before retrying `apm2 fac push`."

    - trigger: "PR has merge conflicts with main"
      observed_via: "`apm2 fac gates` reports merge_conflict_main=FAIL"
      action: "Implementor must rebase or merge main into the branch and resolve conflicts before any further work. Dispatch a fresh implementor agent with conflict resolution instructions."

    - trigger: "Stale SHA — review completed for old commit"
      observed_via: "`apm2 fac doctor --pr <N> --json` shows terminal state but head_sha does not match current PR head"
      action: "Reviews are bound to a specific SHA. If the PR head has advanced, use `apm2 fac restart --pr <N>` to dispatch fresh reviews for the current head."

    - trigger: "CI workflow stuck in a dispatch loop"
      observed_via: "CI check keeps re-running, or status comment is being repeatedly edited"
      action: "Check for corrupt state files (state=corrupt-state). Kill any stale reviewer processes (`ps aux | grep apm2.*fac.*review`). Run `apm2 fac doctor --pr <N> --fix` to repair state, then `apm2 fac restart --pr <N>`. Do not manually delete state files."

invariants[15]:
  - "GitHub PR status, CI check status, and GitHub review state are projections, not truth. They are frequently stale, cached, or out of sync with actual gate results. Always use `apm2 fac doctor --pr <N> --json` as the authoritative orchestration source, with `apm2 fac logs` for line-by-line diagnostics. Never make orchestration decisions based on GitHub API responses alone."
  - "Bounded search: orchestrate only 1-20 PRs per run; >20 requires explicit user partitioning into waves."
  - "One active implementor agent per PR at any time."
  - "At most one active review batch (2 review agents: security + quality) per PR at any time."
  - "All implementor-agent dispatches include a warm handoff with implementor_warm_handoff_required_payload."
  - "Default implementor dispatch starts with `/implementor-default <TICKET_ID or PR_CONTEXT>`."
  - "Implementor handoff prompts use implementor-default as the primary instruction source and add only ticket/PR-specific deltas."
  - "Use fresh fix agents after failed review rounds or stalled progress."
  - "Throughput optimization should be paired with quality countermetrics (reopen rate, rollback count, repeat BLOCKER rate)."
