title: Implementor Default Workflow

decision_tree:
  entrypoint: START
  nodes[6]:
    - id: START
      purpose: "Initialize scope, collect authoritative context, and avoid ambient assumptions."
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables. Replace placeholders like <TICKET_ID>, <PR_NUMBER>, and <WORKTREE_PATH> before running commands."
        - id: RESOLVE_SCOPE
          action: "Resolve target from input: if a ticket id is provided, load that ticket; if a PR number is provided, load PR context plus latest findings."
        - id: LOAD_REQUIRED_READING
          action: "Read SKILL references marked REQUIRED READING and any orchestrator-provided warm handoff files before edits."
        - id: LOAD_REQUIREMENT_BINDINGS
          action: "Read the requirement files bound by the ticket and note acceptance criteria in implementation notes."
        - id: LOAD_MODULE_INVARIANTS
          action: "For every touched crate/module, read local AGENTS.md contracts."
        - id: PLAN_MINIMAL_CHANGESET
          action: "Write a minimal implementation plan that maps each acceptance criterion to concrete file edits and tests."
      next: PRE_EDIT_GATES

    - id: PRE_EDIT_GATES
      purpose: "Apply 5-Whys-derived guardrails before modifying code."
      steps[8]:
        - id: GATE_PRODUCTION_WIRING
          action: "If adding new builders, registries, or gates, verify all production constructor paths wire them; do not rely on test-only injection."
        - id: GATE_FAIL_CLOSED_DEFAULTS
          action: "Check all unknown/missing/error paths in authority/security logic; require explicit deny/failure outcome."
        - id: GATE_TRUST_VALIDATION
          action: "For signatures, digests, seals, or pointer receipts, validate authenticity and binding integrity, not just field shape or non-zero placeholders."
        - id: GATE_MUTATION_ORDERING
          action: "Ensure admission checks execute before irreversible mutations (consume markers, durable commits, state transitions) unless an explicit two-phase protocol exists."
        - id: GATE_NO_SYNTHETIC_CONSTANTS
          action: "Reject hardcoded runtime placeholders (e.g., tick=0, attempts=0, pass verdicts, fixed token counts) on production paths."
        - id: GATE_OPTIONAL_BYPASS
          action: "If gate dependencies are optional types, prove authoritative paths deny when dependency is missing and policy requires it."
        - id: GATE_HASH_PREIMAGE_FRAMING
          action: "For new hash commitments, include length/presence framing for variable fields and include all normative fields."
        - id: GATE_E2E_COVERAGE
          action: "Require at least one test through production dispatch/runtime path for each high-risk change; direct unit checks alone are insufficient."
      next: IMPLEMENT

    - id: IMPLEMENT
      purpose: "Execute the minimal change set while preserving boundary contracts."
      steps[5]:
        - id: APPLY_PATCHES
          action: "Implement the smallest coherent patch that satisfies requirement bindings and pre-edit gates."
        - id: ADD_REGRESSION_TESTS
          action: "Add negative and positive tests for each fixed defect class (missing state, stale state, bypass attempts, replay/order hazards)."
        - id: VERIFY_ERROR_CHANNELS
          action: "Return structured errors for deny paths; avoid logging-and-continuing in authoritative control flow."
        - id: VERIFY_OBSERVABILITY
          action: "Ensure emitted receipts/events include enough fields to audit decisions (hashes, selectors, policy snapshot, reason codes)."
        - id: MINIMIZE_SCOPE_CREEP
          action: "If unrelated issues are found, record follow-up defects/tickets without expanding current patch unless required for correctness."
      next: VERIFY

    - id: VERIFY
      purpose: "Run deterministic verification in required order."
      steps[4]:
        - id: RUN_FMT
          action: "Run `timeout 120s cargo fmt --all`."
        - id: RUN_CLIPPY
          action: "Run `timeout 1200s cargo clippy --workspace --all-targets --all-features -- -D warnings`."
        - id: RUN_DOC
          action: "Run `timeout 1200s cargo doc --workspace --no-deps`."
        - id: RUN_TESTS
          action: "Run `timeout 1800s cargo test --workspace` (or a ticket-scoped subset only when explicitly allowed by ticket scope)."
      next: EMIT_RESULT

    - id: EMIT_RESULT
      purpose: "Produce an auditable result payload for orchestrator and reviewers."
      steps[5]:
        - id: REPORT_CHANGED_FILES
          action: "List changed files and summarize what each change enforces."
        - id: REPORT_COMMAND_RESULTS
          action: "Report pass/fail outcomes for fmt/clippy/doc/test and any scoped test commands."
        - id: REPORT_REQUIREMENT_COVERAGE
          action: "Map each touched requirement to code/test evidence."
        - id: REPORT_RESIDUAL_RISK
          action: "State any unresolved risk, assumption, or deferred work with concrete follow-up ticket ids when available."
        - id: REPORT_BLOCKERS
          action: "If full verification could not run, provide exact reason and smallest next action to unblock."
      next: STOP

    - id: STOP
      purpose: "Terminate with explicit status."
      decisions[2]:
        - id: SUCCESS_STOP
          if: "all required verification steps passed and requirement coverage is complete"
          then:
            stop: "SUCCESS"
        - id: BLOCKED_STOP
          if: "otherwise"
          then:
            stop: "BLOCKED_WITH_EVIDENCE"
