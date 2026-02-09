title: Orchestrator Monitor — Parallel PR Control Loop

decision_tree:
  entrypoint: START
  nodes[8]:
    - id: START
      purpose: "Initialize scope and verify prerequisites before any side effects."
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <...> placeholders with concrete values."
        - id: VERIFY_REPO_AUTH
          action: "Run resolve_repo_root and auth_check from references/commands.md."
        - id: RESOLVE_PR_SCOPE
          action: "If explicit PR numbers were provided, use them. Otherwise run list_open_prs."
        - id: ENFORCE_SCOPE_BOUND
          action: "If scoped open PR count >20, pause and request wave partitioning."
        - id: LOAD_PROFILE
          action: "Select profile from references/scaling-profiles.md based on scoped PR count."
      next: HEARTBEAT_LOOP

    - id: HEARTBEAT_LOOP
      purpose: "Run bounded, evidence-first orchestration ticks until stop condition."
      steps[4]:
        - id: SNAPSHOT
          action: "Capture per-PR fac_review_status + fac_review_project as primary lifecycle signals; use pr_state_json + commit_statuses for metadata/projection cross-checks; use fac_review_tail for recent event stream."
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
          action: "Create this tick's action list using scaling profile limits and priority_order."
      next: EXECUTE_ACTIONS

    - id: EXECUTE_ACTIONS
      purpose: "Apply bounded actions while preventing duplicate workers per PR."
      steps[6]:
        - id: READY_TO_MERGE_ACTION
          action: "For READY_TO_MERGE PRs, run enable_auto_merge."
        - id: REVIEW_MONITOR_ACTION
          action: |
            For REVIEW_MISSING PRs: reviews auto-start via the Forge Admission Cycle CI workflow on push.
            Do NOT manually dispatch reviews. Instead, monitor with `apm2 fac review project --pr <N> --emit-errors`.
            If reviews have not started within 2 minutes of the push, use `apm2 fac review retrigger` as recovery.
            If retrigger also fails, use `apm2 fac review dispatch <PR_URL> --type all` as last-resort fallback.
        - id: FIX_AGENT_ACTION
          action: |
            For CI_FAILED, REVIEW_FAILED, or PR_CONFLICTING PRs with implementor slots, dispatch one fresh fix agent.
            Inject references/common-review-findings.md and references/daemon-implementation-patterns.md in its context.
            Fix agents should use `apm2 fac push` to push their changes — this auto-creates/updates the PR and triggers reviews.
        - id: REVIEW_PROGRESS_ACTION
          action: "For PRs with active reviews, run fac_review_status and fac_review_project; the Forge Admission Cycle workflow remains the GitHub projection path."
        - id: NO_DUPLICATE_OWNERSHIP
          action: "Never run two implementor agents or two review batches for the same PR in the same tick."
      next: STALL_AND_BACKPRESSURE

    - id: STALL_AND_BACKPRESSURE
      purpose: "Contain fanout and recover from stalled workers."
      steps[4]:
        - id: ENFORCE_BACKPRESSURE
          action: "Apply BP01..BP04 from references/scaling-profiles.md before adding new actions."
        - id: STALE_SHA_RECOVERY
          action: "If HEAD changed after review launch, mark old review stale and requeue on new HEAD."
        - id: IDLE_AGENT_RECOVERY
          action: "If an implementor has no progress signal beyond profile idle threshold, replace with fresh agent."
        - id: SATURATION_CHECK
          action: "Use list_review_processes to ensure process fanout remains within profile caps."
      next: EMIT_TICK_EVIDENCE

    - id: EMIT_TICK_EVIDENCE
      purpose: "Record why decisions were taken, not only what was taken."
      steps[3]:
        - id: EMIT_STATUS_DASHBOARD
          action: "Emit current PR states and gate status per PR."
        - id: EMIT_DISPATCH_PLAN
          action: "Emit actions executed this tick and skipped actions with reason (slot cap, conservative gate, stale SHA)."
        - id: EMIT_BLOCKER_LEDGER
          action: "Emit BLOCKED_UNKNOWN entries with evidence needed to unblock."
      next: STOP_OR_CONTINUE

    - id: STOP_OR_CONTINUE
      purpose: "Terminate only on explicit terminal conditions."
      decisions[3]:
        - id: SUCCESS_STOP
          if: "all scoped PRs are MERGED"
          then:
            stop: "SUCCESS"

        - id: PARTIAL_STOP
          if: "all remaining PRs are BLOCKED_UNKNOWN for >=3 consecutive ticks"
          then:
            stop: "PARTIAL_STOP_WITH_BLOCKERS"

        - id: CONTINUE
          if: "otherwise"
          then:
            next: HEARTBEAT_LOOP

    - id: FIX_AGENT_PROMPT_CONTRACT
      purpose: "Ensure implementor agent briefs are consistent and conservatively gated."
      steps[5]:
        - id: INCLUDE_REQUIRED_CONTEXT
          action: |
            Include PR number, branch, HEAD SHA, explicit findings list, and required references:
            references/common-review-findings.md, references/daemon-implementation-patterns.md,
            documents/reviews/CI_EXPECTATIONS.md.
        - id: REQUIRE_BRANCH_SYNC_BEFORE_EDIT
          action: |
            Use this first action sequence before any code edits:
            (1) git fetch origin main
            (2) git rebase origin/main (or git merge origin/main if project policy requires merge commits)
            (3) git diff --name-only --diff-filter=U
            If unmerged files exist, resolve all conflicts first, then continue coding.
        - id: REQUIRE_CONFLICT_EVIDENCE
          action: |
            Ask the subagent to report branch hygiene evidence in output:
            base commit before sync, new base after sync, conflict file list (or explicit 'none').
        - id: ENFORCE_BRANCH_HYGIENE_GATE
          action: |
            If subagent output omits branch sync evidence or reports unresolved conflicts,
            treat the output as incomplete and redispatch a fresh fix subagent.
        - id: REQUIRE_PRE_COMMIT_ORDER
          action: "Run in order: cargo fmt --all; cargo clippy --workspace --all-targets --all-features -- -D warnings; cargo doc --workspace --no-deps; cargo test --workspace."
        - id: REQUIRE_EVIDENCE
          action: "Include exact command results and changed file list in implementor response."
      next: HEARTBEAT_LOOP

    - id: REVIEW_GATE_DEFINITION
      purpose: "Define merge readiness in machine terms."
      steps[1]:
        - id: GATE_RULE
          action: |
            READY_TO_MERGE iff all are true on current HEAD SHA:
            (1) Forge Admission Cycle=success,
            (2) PR mergeable state is not CONFLICTING,
            (3) PR is open and non-draft.
      next: HEARTBEAT_LOOP
