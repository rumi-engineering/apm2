title: Orchestrator Monitor — Parallel PR Control Loop

decision_tree:
  entrypoint: START
  nodes[9]:
    - id: START
      purpose: "Initialize scope and verify prerequisites before any side effects."
      steps[5]:
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
            (6) `apm2 fac review project --help`
            (7) `apm2 fac review tail --help`
            (8) `apm2 fac logs --help`
            (9) `apm2 fac gates --help`
            (10) `apm2 fac push --help`
            (11) `apm2 fac restart --help`
            Help output is authoritative for names/flags.
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
          action: "Capture per-PR fac_review_status + fac_review_project as primary lifecycle signals; use fac_logs and fac_review_tail for diagnosis context."
        - id: COLLECT_FINDINGS_FROM_FAC
          action: |
            For each PR, fetch structured findings via FAC:
            `apm2 fac review findings --repo <OWNER/REPO> --pr <PR_NUMBER> --json`
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
            Do NOT manually dispatch reviews. Instead, monitor with `apm2 fac review project --pr <N> --emit-errors`.
            If reviews have not started within 2 minutes of the push, use `apm2 fac restart --pr <PR_NUMBER>` as recovery.
        - id: FIX_AGENT_ACTION
          action: |
            For CI_FAILED, REVIEW_FAILED, or PR_CONFLICTING PRs with implementor slots, dispatch one fresh fix agent
            with `/implementor-default <TICKET_ID or PR_CONTEXT>`.
            Inject @documents/skills/implementor-default/SKILL.md in its context.
            Fix agents should use `apm2 fac push` to push their changes — this auto-creates/updates the PR and triggers reviews.
        - id: REVIEW_PROGRESS_ACTION
          action: "For PRs with active reviews, run fac_review_status + fac_review_project; the Forge Admission Cycle workflow remains the GitHub projection path."
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
          action: "Build explicit findings list from `apm2 fac review findings --repo <OWNER/REPO> --pr <PR_NUMBER> --json` output and include it in handoff."
        - id: INCLUDE_REQUIRED_CONTEXT
          action: |
            Include PR number, branch, HEAD SHA, explicit findings list, and required references:
            @documents/skills/implementor-default/SKILL.md,
            documents/reviews/FAC_LOCAL_GATE_RUNBOOK.md.
        - id: REQUIRE_BRANCH_SYNC_BEFORE_EDIT
          action: |
            Require implementor-owned worktree health loop before any code edits:
            (1) choose/create the intended worktree path,
            (2) synchronize branch ancestry with current mainline policy,
            (3) reduce merge-conflict count to zero,
            (4) proceed only when worktree is conflict-free.
            Do NOT prescribe raw git/gh commands in orchestrator prompts.
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
            (1) `apm2 fac review project --pr <PR_NUMBER> --emit-errors` reports terminal pass state,
            (2) no FAC projection error lines indicate CI/review failure,
            (3) PR is still observed in FAC lifecycle projections.
      next: HEARTBEAT_LOOP

    - id: STOP
      purpose: "Terminate."
      steps[1]:
        - id: DONE
          action: "output DONE and nothing else, your task is complete."
