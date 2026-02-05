title: RFC Orchestrator — Governance Principles

purpose: |
  Consolidates applicable Holonic Laws and Reasoning Modes that govern
  orchestrator decision-making, state management, and failure handling.
  These principles are not optional guidelines—they are the "physics"
  within which the orchestrator operates.

holonic_laws:
  tier_1_directly_applicable:
    - id: LAW-01
      name: Loop Closure & Gated Promotion
      relevance: "Orchestrator IS the loop closer. Gate receipts for state transitions."
      operationalization:
        - rule: "Risk-Tiered Closure"
          application: |
            - Low-Risk: Batched sensing for throughput (e.g., status checks).
            - High-Risk: Promotion to 'merged' requires explicit gate receipts.
        - rule: "Receipts"
          application: |
            Every state transition (AWAITING_IMPLEMENTATION → AWAITING_REVIEWS →
            AWAITING_FIXES → AWAITING_MERGE → TICKET_COMPLETE) must produce a
            machine-readable receipt: {ticket_id, from_state, to_state, timestamp, evidence}.
        - rule: "Hierarchical Gate Separation"
          application: |
            Orchestrator (Planner) and Implementer (Executor) operate under distinct
            gate sets. Implementer outputs verified against quality/security gates
            before admission to merged state.

    - id: LAW-03
      name: Monotone Ledger
      relevance: "Event sourcing for ticket state. No silent mutations."
      operationalization:
        - rule: "Fact Submission"
          application: |
            Orchestrator produces state transition events, not state overwrites.
            State is derived by replaying events from initial conditions.
        - rule: "Memory Mutation as Ledger Events"
          application: |
            State changes (current_ticket, merged_count, last_pr_state) are logged
            as events: {event_type, timestamp, old_value, new_value}.
        - rule: "No Silent Mutations"
          violation: "SILENT_STATE_MUTATION defect if state changes without event log."

    - id: LAW-05
      name: Dual-Axis Containment
      relevance: "Capability leases for subagents, tool allowlists, context firewalls."
      operationalization:
        - rule: "ContextRead Firewalls"
          application: |
            Subagents receive scoped ContextPacks limited to their ticket.
            No access to other tickets' state or orchestrator internals.
        - rule: "Interface Variety Control"
          application: |
            Subagents receive constrained tool allowlists:
            - Implementer: file ops, git ops, test execution
            - Reviewer: read-only file access, comment posting
        - rule: "Time-Bounded Capability Leases"
          application: |
            Subagent dispatch includes implicit lease: capability expires when
            Task tool returns. Fresh agent = fresh lease (no capability accumulation).

    - id: LAW-11
      name: Idempotent Actuation
      relevance: "All dispatcher commands must be replay-safe with idempotency keys."
      operationalization:
        - rule: "Idempotency"
          application: |
            All orchestrator commands are idempotent:
            - DISPATCH_IMPLEMENTER: re-dispatch safe (prior agent terminated first)
            - TRIGGER_REVIEWS: re-trigger safe (reviews are additive)
            - KILL_REVIEWER: re-kill safe (pkill || true)
        - rule: "Replay Safety"
          application: |
            If orchestrator crashes mid-tick, restart resumes from last known state.
            No command should corrupt state on double-execution.
        - rule: "Execution Receipts"
          application: |
            Each dispatch produces receipt: {command, timestamp, idempotency_key, result}.

    - id: LAW-12
      name: Bounded Search & Termination
      relevance: "Progress signals, lease timeouts. NO iteration limits per user request."
      operationalization:
        - rule: "Progress Signals"
          application: |
            Every 30s heartbeat captures: {tick_count, current_state, last_transition_time}.
            Stagnation detected if same state for >N ticks without progress indicator change.
        - rule: "Stop Conditions"
          application: |
            Only STOP_ALL_MERGED is valid termination. All other conditions are recoverable.
            See: references/stop-conditions.md
        - rule: "Defect Tracking"
          application: |
            Non-convergent loops (implementer repeatedly failing same test) produce
            UNBOUNDED_SEARCH DefectRecord with hypothesis: {stuck_pattern, attempted_fixes}.
        - rule: "NO ITERATION LIMITS"
          application: |
            User explicitly requested: 20+ rounds of iteration is normal and expected.
            Progress is measured by hypothesis elimination and test pass rate, not iteration count.

    - id: LAW-06
      name: MDL as a Gated Budget
      relevance: "Context window is a hard resource constraint. Subagents must handoff before exhaustion."
      operationalization:
        - rule: "Context Budget Threshold"
          application: |
            Subagent context usage is monitored. At 175k tokens:
            1. Terminate current subagent gracefully
            2. Extract handoff context: {ticket_id, work_completed, work_remaining, last_state}
            3. Spawn fresh agent with warm start prompt
        - rule: "MDL Ceiling Enforcement"
          application: |
            If description of "how to work" exceeds context window W, agent WILL fail.
            Orchestrator MUST emit recovery action (warm handoff) before this occurs.
        - rule: "No Work Loss"
          application: |
            Context exhaustion is a recoverable condition. Warm handoff preserves:
            - What was accomplished (files changed, tests passing)
            - What remains (from ticket requirements)
            - Last error or action (for continuity)
        - rule: "Handoff Context Format"
          application: |
            handoff_context: {
              ticket_id: "TCK-XXXXX",
              work_completed: "summary of completed work",
              work_remaining: "summary of remaining work",
              last_error: "error if terminated due to failure",
              last_action: "last successful action"
            }

  tier_2_important_context:
    - id: LAW-02
      name: Observable Context Sufficiency
      relevance: "ContextPack design, pack-miss metrics."
      application: |
        Track pack-miss rate: frequency of subagents requesting context not in their pack.
        High pack-miss → ContextPack design defect.

    - id: LAW-04
      name: Stochastic Stability
      relevance: "Evidence bundles, handling CI flakiness as verification defect."
      application: |
        Flaky CI is a first-class defect (FLAKY_VERIFIER). Don't blame implementer
        for test nondeterminism. Retry with fresh runner before attributing failure
        to code change.

    - id: LAW-09
      name: Temporal Pinning
      relevance: "Snapshot freshness policies, drift detection."
      application: |
        PR state snapshots are point-in-time. SHA mismatch between reviewer claim
        and current HEAD indicates drift → retrigger reviews on fresh snapshot.

    - id: LAW-14
      name: Risk-Weighted Evidence
      relevance: "Tier-based gate selection (T0/T1/T2/T3)."
      application: |
        Security-critical changes require T3 gates (strongest verification + fail-closed posture).
        Production changes require T2 gates with replay/stop enforcement.
        Documentation-only changes may use T0 gates (static analysis only).

reasoning_modes:
  tier_1_core_orchestration:
    - id: 66
      name: Temporal
      application: "State transition verification with temporal constraints and preconditions."
      orchestrator_use:
        - "Verify preconditions hold at transition time (e.g., PR exists before AWAITING_REVIEWS)"
        - "Track state persistence: PR_OPEN holds from creation until merge/close"
        - "Detect invalid orderings: cannot transition to AWAITING_FIXES without prior AWAITING_REVIEWS"
      key_outputs:
        - persistence_frame: "[state, holds_from, invalidated_by, current_status]"
        - state_transition_log: "[trigger_event, preconditions, state_before, state_after, timestamp]"

    - id: 47
      name: Planning/Policy
      application: "Orchestration playbooks with contingencies and rollback paths."
      orchestrator_use:
        - "HEARTBEAT_TICK is a policy: state → action mapping for all reachable states"
        - "Each state has defined action and contingency branches"
        - "Checkpoint every tick with progress assessment"
      key_outputs:
        - policy: "state → action mapping covering all states in CLASSIFY_STATE"
        - contingency_table: "[failure_condition, recovery_action] for each recoverable state"

    - id: 41
      name: Diagnostic
      application: "Structured failure triage with hypothesis ranking and discriminating tests."
      orchestrator_use:
        - "When implementer fails: generate >=3 hypotheses from fault model"
        - "Discriminating tests: check logs, diff PR, compare to previous failures"
        - "Don't assume first plausible cause; require evidence"
      fault_model:
        common_failures:
          - "Test failure (code defect)"
          - "CI flakiness (verifier defect)"
          - "Merge conflict (drift)"
          - "Auth/permission error (infrastructure)"
          - "Reviewer SHA mismatch (stale review)"
        discriminating_tests:
          - "Retry on fresh runner → distinguishes flaky vs real failure"
          - "Check commit timestamps → distinguishes drift vs code issue"
          - "Compare HEAD SHA to reviewer report → distinguishes stale vs current"

    - id: 75
      name: Meta-Reasoning
      application: "Mode selection for different problem types (time pressure, stakes, novelty)."
      orchestrator_use:
        - "Characterize each problem on 5 axes before selecting reasoning approach"
        - "Budget meta-reasoning to <5% of analysis time"
        - "Default to Diagnostic for failures, Policy for state transitions"
      problem_classification:
        axes:
          - "belief vs action"
          - "cooperative vs adversarial"
          - "certainty vs exploration"
          - "time pressure (H/M/L)"
          - "stakes (H/M/L)"
        orchestrator_defaults:
          state_transition: "Policy (action, cooperative, certainty, L, M)"
          failure_triage: "Diagnostic (belief, cooperative, exploration, M, H)"
          rogue_detection: "Adversarial (action, adversarial, certainty, H, H)"

  tier_2_decision_failure:
    - id: 28
      name: Prototype/Similarity
      application: "State classification via similarity to exemplar ticket states."
      orchestrator_use: |
        CLASSIFY_STATE uses prototype matching: current ticket state compared against
        canonical exemplars (NO_TICKET, NO_PR, HAS_PR variants).

    - id: 45
      name: Decision-Theoretic
      application: "Dispatch decisions when multiple options exist."
      orchestrator_use: |
        When blocked on multiple fronts, prioritize by expected value:
        - Unblock highest-value ticket first (dependencies unlock others)
        - Prefer fast wins when value is equal

    - id: 74
      name: Clinical Troubleshooting
      application: "High-severity incident response (P1/P2)."
      orchestrator_use: |
        For critical failures (main branch corrupted, all PRs blocked):
        Switch from methodical Diagnostic to Clinical mode—parallel fix+diagnose.

    - id: 49
      name: Robust/Worst-Case
      application: "SLA guarantee design, failure mode enumeration."
      orchestrator_use: |
        Design for worst-case: assume subagents will fail, reviewers will be slow,
        CI will flake. Recovery paths exist for all enumerated failure modes.

state_transition_receipts:
  format:
    ticket_id: "TCK-XXXXX"
    from_state: "AWAITING_IMPLEMENTATION | AWAITING_REVIEWS | AWAITING_FIXES | AWAITING_MERGE"
    to_state: "AWAITING_REVIEWS | AWAITING_FIXES | AWAITING_MERGE | TICKET_COMPLETE"
    timestamp: "ISO8601"
    trigger: "event that caused transition"
    evidence:
      pr_sha: "commit SHA at transition time"
      review_status: "APPROVED | CHANGES_REQUESTED | PENDING"
      ci_status: "PASS | FAIL | PENDING"
    preconditions_verified:
      - "precondition 1: true"
      - "precondition 2: true"

  preconditions_by_transition:
    to_AWAITING_REVIEWS:
      - "PR exists and is OPEN"
      - "At least one commit on PR branch"
    to_AWAITING_FIXES:
      - "Reviews exist with CHANGES_REQUESTED or CI failed"
    to_AWAITING_MERGE:
      - "All reviews APPROVED"
      - "All CI checks PASS"
      - "No merge conflicts"
    to_TICKET_COMPLETE:
      - "PR state is MERGED"

defect_records:
  unbounded_search:
    trigger: "Same test failing >5 consecutive implementer attempts with same error"
    fields:
      defect_type: "UNBOUNDED_SEARCH"
      stuck_pattern: "description of repeated failure"
      attempted_fixes: "[list of implementer attempts]"
      hypothesis: "why it might be stuck"
    action: "Emit DefectRecord, continue with fresh approach or escalate"

  silent_state_mutation:
    trigger: "State changed without corresponding event log entry"
    fields:
      defect_type: "SILENT_STATE_MUTATION"
      mutated_field: "field that changed"
      expected_event: "event that should have been logged"
    action: "Log corrective event, investigate root cause"

  flaky_verifier:
    trigger: "Same test passes and fails on identical code"
    fields:
      defect_type: "FLAKY_VERIFIER"
      test_name: "flaky test identifier"
      pass_count: "N"
      fail_count: "M"
    action: "Retry on fresh runner, mark test as flaky in tracking"

  reviewer_sha_mismatch:
    trigger: "Reviewer reports reviewing SHA X but HEAD is SHA Y"
    fields:
      defect_type: "REVIEWER_SHA_MISMATCH"
      reported_sha: "SHA from reviewer"
      actual_sha: "current HEAD"
    action: "Kill reviewer, retrigger reviews on current HEAD"

  context_exhaustion:
    trigger: "Subagent context usage exceeds 175k tokens"
    fields:
      defect_type: "CONTEXT_EXHAUSTION"
      ticket_id: "ticket being worked"
      tokens_used: "approximate token count at termination"
      work_completed: "summary of completed work"
      work_remaining: "summary of remaining work"
    action: "Terminate subagent, generate handoff_context, spawn fresh agent with warm start"
    recovery: |
      1. Extract handoff context from subagent's final state
      2. Dispatch fresh agent with prompt: /ticket <id> + ## Warm Handoff Context
      3. Fresh agent continues from documented state
