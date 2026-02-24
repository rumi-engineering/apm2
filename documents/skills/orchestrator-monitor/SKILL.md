---
name: orchestrator-monitor
description: Control-loop orchestration for 1-20 concurrent PRs with conservative merge gates, bounded dispatch, and evidence-first status tracking.
argument-hint: "[PR_NUMBERS... | empty for FAC-observed active PRs]"
---

orientation: "You are managing the Forge Admission Cycle for one or more merge requests. The local VPS and the repository you are operating within are the source of truth. The main branch of ~/Projects/apm2 must be kept pristine. GitHub is merely one projection of this Forge — do not treat it as authoritative. Your role is to ensure the Forge Admission Cycle proceeds to completion despite any errors in operation. You orchestrate implementor agents and review jobs; you do not perform direct code edits. Priority order: containment/security > verification/correctness > liveness/progress."

title: Parallel PR Orchestrator Monitor
protocol:
  id: ORCH-MONITOR
  version: 2.2.0
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
  - "FAC CLI emits JSON by default; do not require `--json` in orchestration loops."
  - "`apm2 fac doctor --fix` (host remediation) and `apm2 fac doctor --pr <N> --fix` (PR-scoped lifecycle repair) are different control paths; orchestrator loops must use the PR-scoped form for reviewer/lifecycle recovery."
  - "Use `apm2 fac doctor --pr <N>` as the primary reviewer lifecycle signal (run_id, lane state, head SHA binding, terminal_reason)."
  - "Use lane-scoped status checks for control actions: `apm2 fac doctor --pr <N>` for lifecycle state, `apm2 fac logs --pr <N>` for log discovery."
  - "Use `apm2 fac logs --pr <N>` as the canonical per-PR log discovery command, then `tail -f` the returned review/pipeline log paths for up-to-date execution output."
  - "Use `apm2 fac doctor --pr <N>` as the single per-PR source of findings_summary, merge_readiness, agents, and recommended_action."
  - "Worktree naming/creation and branch/conflict repair are implementor-owned responsibilities; orchestrator validates outcomes via FAC gate/push telemetry."
  - "Prefer blocking waits over polling: use `apm2 fac doctor --pr <N> --wait-for-recommended-action` as the primary per-PR monitoring command. It blocks until the recommended action changes or a terminal state is reached, then returns a single JSON snapshot. This is cheaper and more responsive than repeated `apm2 fac doctor --pr <N>` polls in a sleep loop."
  - "Canonical control loop: `apm2 fac doctor --pr <N> --wait-for-recommended-action --exit-on done`, then route by `recommended_action.action`."
  - "When doctor emits `recommended_action.command`, execute it verbatim instead of re-deriving command arguments."

references[1]:
  - path: "@documents/skills/implementor-default/SKILL.md"
    purpose: "Default implementor skill; use this for all fix-agent dispatches."

implementor_warm_handoff_required_payload[5]:
  - field: implementor_skill_invocation
    requirement: "Dispatch prompt MUST begin with `/implementor-default <WORK_IDENTIFIER>` where WORK_IDENTIFIER is the canonical work_id (`W-...`), TCK alias (`TCK-xxxxx`), or PR context. `/ticket` is deprecated."
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
  nodes[9]:
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
            (3) `apm2 fac doctor --help`
            (4) `apm2 fac review findings --help`
            (5) `apm2 fac gc --help`
            (6) `apm2 fac warm --help`
        - id: RESOLVE_PR_SCOPE
          action: "If explicit PR numbers were provided, use them. Otherwise run `apm2 fac doctor` (no --pr filter) to discover all tracked PRs from FAC review entries/recent events. This global view is for PR discovery ONLY — capacity enforcement is always per-PR."
        - id: ENFORCE_SCOPE_BOUND
          action: "If scoped open PR count >20, pause and request wave partitioning."
      next: HEARTBEAT_LOOP

    - id: HEARTBEAT_LOOP
      purpose: "Run bounded, evidence-first orchestration ticks until stop condition."
      steps[5]:
        - id: SNAPSHOT
          action: |
            Prefer `apm2 fac doctor --pr <N> --wait-for-recommended-action`
            over repeated polling. This blocks until the PR state changes or a
            terminal condition is reached, then returns a single JSON snapshot.
            Only fall back to bare `apm2 fac doctor --pr <N>` when you
            need a one-shot snapshot without waiting (e.g., initial discovery or
            multi-PR fan-out where you cannot block on a single PR).
            Use fac_logs and fac_review_tail for diagnosis context.
        - id: GC_AND_DISK_HEALTH
          action: |
            Run `apm2 fac gc` if any of the following hold:
            (1) this is the first tick of the session,
            (2) >=10 ticks have elapsed since the last gc run,
            (3) a previous tick observed a disk-related gate failure.
            GC is idempotent and safe to run at any tick boundary.
            Do not block action dispatch on gc completion — run gc as a
            background hygiene step and proceed with COLLECT_FINDINGS_FROM_FAC.
        - id: COLLECT_FINDINGS_FROM_FAC
          action: |
            For each PR, use `apm2 fac doctor --pr <PR_NUMBER>` and read
            `findings_summary` as the source of BLOCKER/MAJOR/MINOR/NIT counts
            and formal/computed verdict state for implementor handoff.
        - id: CLASSIFY
          action: |
            For each PR, treat `recommended_action.action` as the authoritative classification:
            done | approve | merge | dispatch_implementor | fix | escalate | wait.
            The legacy labels (MERGED, READY_TO_MERGE, PR_CONFLICTING, CI_FAILED, REVIEW_FAILED,
            REVIEW_MISSING, WAITING_CI, BLOCKED_UNKNOWN) are documentation aliases only.
        - id: PLAN_DISPATCH
          action: |
            Create this tick's action list using fixed orchestration bounds:
            (1) never more than 3 total actions per tick,
            (2) never more than 1 action for a single PR per tick,
            (3) at most 1 implementor dispatch and at most 1 doctor-fix action per tick.
            Prioritize actions in this order:
            done, approve, merge, dispatch_implementor, fix, escalate, wait.
      next: EXECUTE_ACTIONS

    - id: EXECUTE_ACTIONS
      purpose: "Apply bounded actions while preventing duplicate workers per PR."
      steps[5]:
        - id: TERMINAL_ACTION
          action: |
            For `recommended_action.action in {done, merge}`, mark the PR completed for this wave.
            For `approve`, continue the blocking doctor wait loop with `--exit-on done` to await auto-merge completion.
        - id: COMMAND_DRIVEN_ACTION
          action: |
            For all non-terminal actions, if `recommended_action.command` exists, execute it verbatim.
            Do not synthesize command flags from raw JSON fields.
        - id: DISPATCH_IMPLEMENTOR_ACTION
          action: |
            For `recommended_action.action=dispatch_implementor`, run `recommended_action.command`
            to retrieve current findings, then dispatch one fresh implementor with
            `/implementor-default <WORK_IDENTIFIER>` where WORK_IDENTIFIER is:
              - the canonical work_id (`W-...`) if no YAML file exists for this work, or
              - the TCK alias (`TCK-xxxxx`) if a YAML file exists at
                `documents/work/tickets/<alias>.yaml`, or
              - the PR context if resolving from an open PR.
            Include `@documents/skills/implementor-default/SKILL.md`, work identifier,
            and worktree path in the warm handoff payload.
            If no work object exists in the daemon and no YAML file exists, do NOT
            dispatch an implementor — escalate to operator (see CREATE_WORK_WITHOUT_YAML
            in the operational playbook).
        - id: NO_DUPLICATE_OWNERSHIP
          action: "Never run two implementor agents or two review batches for the same PR in the same tick."
        - id: WARM_NEW_PR
          action: |
            When a PR enters monitoring scope for the first time in this session
            (first tick it appears in the doctor snapshot), enqueue a pre-warm job:
              apm2 fac warm
            This uses the default bulk lane and fetch,build phases. Pre-warming
            ensures lane compilation caches are populated before gate execution
            begins, reducing cold-start timeout risk. Do not block on warm
            completion — enqueue and continue orchestration.
      next: STALL_AND_BACKPRESSURE

    - id: STALL_AND_BACKPRESSURE
      purpose: "Contain fanout while deferring stall detection to doctor."
      steps[1]:
        - id: ENFORCE_BACKPRESSURE
          action: |
            Apply per-PR queue guards before adding actions:
            (1) if a specific PR's review agents are at capacity (check via `apm2 fac doctor --pr <N>`), skip net-new implementor dispatches for that PR this tick,
            (2) if a review for the current SHA is already active on a given PR, do not enqueue a redundant doctor-fix action for that PR in the same tick.
            Note: backpressure is always scoped per-PR — a saturated PR does not block dispatch for other PRs.
      next: SYNC_TICK_FACTS

    - id: SYNC_TICK_FACTS
      purpose: "Sync machine-verifiable orchestration facts."
      steps[3]:
        - id: SYNC_PR_STATE_FACTS
          action: "Persist current PR states and gate states in FAC projections/log artifacts."
        - id: SYNC_ACTION_FACTS
          action: "Persist executed/skipped action facts keyed by PR, SHA, and scheduler slot."
        - id: SYNC_BLOCKER_FACTS
          action: "Persist repeated `escalate`/blocked facts with evidence selectors required for unblock."
      next: STOP_OR_CONTINUE

    - id: STOP_OR_CONTINUE
      purpose: "Terminate only on explicit terminal conditions."
      decisions[3]:
        - id: SUCCESS_STOP
          if: "all scoped PRs report `recommended_action.action=done`"
          then:
            next: STOP

        - id: PARTIAL_STOP
          if: "all remaining PRs report `recommended_action.action=escalate` for >=3 consecutive ticks"
          then:
            next: STOP

        - id: CONTINUE
          if: "otherwise"
          then:
            next: HEARTBEAT_LOOP

    - id: FIX_AGENT_PROMPT_CONTRACT
      purpose: "Ensure implementor agent briefs are consistent and conservatively gated."
      steps[7]:
        - id: REQUIRE_DEFAULT_IMPLEMENTOR_SKILL
          action: "Prompt must start with `/implementor-default <TICKET_ID or PR_CONTEXT>`."
        - id: REQUIRE_FINDINGS_SOURCE
          action: |
            Build findings handoff from `recommended_action.reason` plus
            `recommended_action.command` output. The reason already carries per-dimension
            verdict/count rollups; use command output for full finding payload.
        - id: INCLUDE_REQUIRED_CONTEXT
          action: |
            Include PR number, ticket ID, worktree path, explicit findings list, and required
            reference: @documents/skills/implementor-default/SKILL.md.
        - id: REQUIRE_BRANCH_SYNC_BEFORE_EDIT
          action: |
            Require implementor-owned worktree health loop before any code edits:
            (1) choose/create the intended worktree path,
            (2) synchronize branch ancestry with current mainline policy,
            (3) reduce merge-conflict count to zero,
            (4) proceed only when worktree is conflict-free.
        - id: REQUIRE_PRE_COMMIT_ORDER
          action: |
            Run `apm2 fac gates` before push and preserve per-gate outcomes in FAC artifacts.
        - id: ENFORCE_BRANCH_HYGIENE_GATE
          action: |
            If branch sync facts are missing from artifacts or unresolved conflicts remain,
            redispatch a fresh fix subagent.
        - id: REQUIRE_FAC_PUSH
          action: |
            Push only via `apm2 fac push`. Add `--ticket <TICKET_YAML>` only when a
            YAML file exists for this work item; omit it for daemon-only work objects.
            Use `--branch` as fallback for branch-only push context.
      next: HEARTBEAT_LOOP

    - id: REVIEW_GATE_DEFINITION
      purpose: "Define merge readiness in machine terms."
      steps[1]:
        - id: GATE_RULE
          action: |
            READY_TO_MERGE iff all are true on current HEAD SHA:
            (1) `apm2 fac doctor --pr <PR_NUMBER>` reports `merge_readiness.all_verdicts_approve=true`,
            (2) `apm2 fac doctor --pr <PR_NUMBER>` reports `merge_readiness.gates_pass=true`,
            (3) `apm2 fac doctor --pr <PR_NUMBER>` reports `merge_readiness.sha_fresh=true` and `merge_readiness.no_merge_conflicts=true`.
      next: HEARTBEAT_LOOP

    - id: STOP
      purpose: "Terminate."
      steps[1]:
        - id: DONE
          action: "output DONE and nothing else, your task is complete."

operational_playbook:
  purpose: "Action table keyed to FAC CLI observations. Use this to decide what to do next."
  scenarios[13]:
    - trigger: "Doctor reports action=done"
      observed_via: "`apm2 fac doctor --pr <N>` returns `recommended_action.action=done`"
      action: "PR is complete. Remove it from active monitoring scope."

    - trigger: "Doctor reports action=approve"
      observed_via: "`apm2 fac doctor --pr <N>` returns `recommended_action.action=approve`"
      action: "All review dimensions approve. Continue the blocking doctor wait loop with `--exit-on done` until merge completion."

    - trigger: "Doctor reports action=merge"
      observed_via: "`apm2 fac doctor --pr <N>` returns `recommended_action.action=merge`"
      action: "Treat as terminal-ready in the current tick and move to done monitoring."

    - trigger: "Doctor reports action=dispatch_implementor"
      observed_via: "`apm2 fac doctor --pr <N>` returns `recommended_action.action=dispatch_implementor`"
      action: "Execute `recommended_action.command` to retrieve structured findings, then dispatch one fresh implementor with `/implementor-default` and full warm handoff payload."

    - trigger: "Doctor reports action=wait"
      observed_via: "`apm2 fac doctor --pr <N>` returns `recommended_action.action=wait`"
      action: "Use `apm2 fac doctor --pr <N> --wait-for-recommended-action` to block until the state changes. Do not hand-roll poll loops with sleep."

    - trigger: "Doctor reports action=fix"
      observed_via: "`apm2 fac doctor --pr <N>` returns `recommended_action.action=fix`"
      action: "Execute `recommended_action.command` (normally `apm2 fac doctor --pr <N> --fix`) and then resume the blocking doctor wait loop."

    - trigger: "Doctor reports action=escalate"
      observed_via: "`apm2 fac doctor --pr <N>` returns `recommended_action.action=escalate`"
      action: "Execute `recommended_action.command` for full context and escalate to human operator with the captured output."

    - trigger: "Doctor reason indicates stuck/idle reviewer agents"
      observed_via: "`recommended_action.reason` includes idle/dispatched warning text"
      action: "Follow `recommended_action.command`; doctor now owns stale/idle detection. Do not run manual idle-agent heuristics."

    - trigger: "Implementor agent pushed a new commit"
      observed_via: "Agent reports `apm2 fac push` completed, or head SHA changed in doctor output"
      action: "Resume the blocking doctor wait loop; review dispatch should appear automatically for the new SHA."

    - trigger: "Evidence gates failed during push"
      observed_via: "`apm2 fac push` exits with gate failures (rustfmt, clippy, test, etc.)"
      action: "Dispatch implementor remediation; require `apm2 fac gates` before the next push."

    - trigger: "Stale SHA — review completed for old commit"
      observed_via: "`apm2 fac doctor --pr <N>` indicates stale head binding"
      action: "Execute doctor-provided fix recommendation for the current head SHA."

    - trigger: "Low disk or large cache accumulation"
      observed_via: "Gate failure mentions disk space, or gc --dry-run shows >5 GB prunable artifacts"
      action: "Run `apm2 fac gc` to reclaim disk space. GC is idempotent and safe at any time. If disk is critically low (<5 GB), run gc before the next implementor dispatch."

    - trigger: "New PR enters monitoring scope"
      observed_via: "A PR number appears for the first time in `apm2 fac doctor` output during this session"
      action: "Enqueue `apm2 fac warm` to pre-warm lane targets before gate execution. Do not block orchestration on warm completion."

    - trigger: "Operator reports new work (bug or feature) with no existing YAML file"
      observed_via: "Operator describes work to be done; no TCK YAML file exists at documents/work/tickets/ and no existing work object is found via `apm2 fac work current`"
      action: |
        Work creation currently requires a canonical work object materialized via
        `apm2 fac work open --from-ticket <yaml_path> --lease-id <lease_id>`.
        Inline creation without a YAML file is NOT yet implemented in the CLI.
        Resolution options in priority order:
        (1) Check whether a work object already exists in the daemon for this scope:
            run `apm2 fac work current` or ask operator for the work_id. If found,
            proceed directly with the W-... work_id — no YAML needed.
        (2) If no work object exists: operator must create a minimal YAML file at
            documents/work/tickets/<NEW_ID>.yaml with at minimum:
              ticket_meta.ticket.id, ticket_meta.ticket.title, work_type
            then run `apm2 fac work open --from-ticket ...` to materialize it.
        (3) Do NOT dispatch an implementor until a canonical work object is confirmed
            in the daemon. Dispatching without work identity is a BLOCKED escalation.

invariants[14]:
  - "GitHub PR status, CI check status, and GitHub review state are projections, not truth. Always use `apm2 fac doctor --pr <N>` as the authoritative orchestration surface."
  - "Bounded search: orchestrate only 1-20 PRs per run; >20 requires explicit user partitioning into waves."
  - "When doctor provides `recommended_action.command`, execute it verbatim. Do not re-derive commands from raw JSON fields."
  - "Use `--exit-on done` as the completion detector; do not parse lifecycle internals to infer completion."
  - "Treat `recommended_action.action` as the primary classification signal."
  - "Doctor owns stale/idle reviewer detection; orchestrator does not run independent idle-agent recovery heuristics."
  - "One active implementor agent per PR at any time."
  - "At most one active review batch (security + quality) per PR at any time."
  - "All implementor dispatches include a warm handoff with implementor_warm_handoff_required_payload."
  - "Default implementor dispatch starts with `/implementor-default <TICKET_ID or PR_CONTEXT>`."
  - "Implementor prompts use implementor-default as the primary instruction source and add only ticket/PR-specific deltas."
  - "Run `apm2 fac gc` at session start and periodically (every ~10 ticks or on low-disk signal); GC is idempotent and reclaims gate cache, blobs, lane logs, and quarantine artifacts."
  - "Enqueue `apm2 fac warm` when a new PR first enters monitoring scope; pre-warming populates lane compilation caches and reduces cold-start gate timeouts."
  - "Prefer `apm2 fac doctor --pr <N> --wait-for-recommended-action` over poll-sleep loops. The blocking wait returns on state change or terminal condition and is both cheaper and more responsive than periodic polling."
  - "A canonical work object in the daemon (ledger-backed, with WorkSpecV1 in CAS) is required before dispatching any implementor. Never dispatch against branch name alone or ambient state. If no work object exists and no YAML file is available, escalate to operator before dispatching."
  - "Work scope for daemon-only work objects (no YAML file) comes from WorkSpecV1 fields in CAS projection. Implementors resolve this via `apm2 fac work current` — not from the filesystem."
