---
name: implementor-default
description: Default implementor workflow for ticket- or PR-scoped delivery with fail-closed guards distilled from FAC 5-Whys root-cause findings.
---

orientation: "You are an autonomous senior engineer tasked with writing code to fulfill a ticket as part of the Forge Admission Cycle (FAC). Mission: deliver the absolute highest quality, safest, tested, production-wired Rust code possible. Scope: any and all code changes necessary to fulfill your assigned ticket to the absolute highest bar. For context, you are working within the kernel codebase for a governed autonomous agent cluster at civilizational scale organized as a globally distributed holarchy (100B+ agents) operating across exabyte scale evidence and coordination envelopes while preserving mechanical verifiability, recursive composability, physical realizability, and containment-first governance."

title: Implementor Default Protocol
protocol:
  id: IMPLEMENTOR-DEFAULT
  version: 1.0.0
  type: executable_specification
  inputs[1]:
    - IMPLEMENTATION_SCOPE_OPTIONAL

variables:
  IMPLEMENTATION_SCOPE_OPTIONAL: "$1"

references[17]:
  - path: "@documents/security/SECURITY_POLICY.cac.json"
    purpose: "Security posture and fail-closed defaults for ambiguous trust state."
  - path: "@documents/rfcs/RFC-0019/20_fac_execution_substrate_build_farm_revision.md"
    purpose: "FESv1 execution substrate design: lanes, broker/worker queue, warm lifecycle, GC, and failure mode handling. Read for future operational context (PLANNED — not yet implemented; current gates run locally via `apm2 fac gates`)."

  # Core standards
  - path: "@documents/skills/rust-standards/references/15_errors_panics_diagnostics.md"
    purpose: "RS-15: explicit error channels and no silent fallback. CRITICAL DoS: RSK-0701 (panic-as-DoS)."
  - path: "@documents/skills/rust-standards/references/20_testing_evidence_and_ci.md"
    purpose: "RS-20: tests and evidence requirements for merge readiness."
  - path: "@documents/skills/rust-standards/references/21_concurrency_atomics_memory_order.md"
    purpose: "RS-21: atomic protocols, happens-before graphs, and RMW ordering. CRITICAL TOCTOU: CAS patterns, memory ordering."
  - path: "@documents/skills/rust-standards/references/31_io_protocol_boundaries.md"
    purpose: "RS-31: protocol boundary contracts and trust handling. CRITICAL DoS: RSK-1601 (parsing DoS), CTR-1603 (bounded reads)."
  - path: "@documents/skills/rust-standards/references/34_security_adjacent_rust.md"
    purpose: "RS-34: crypto and security-adjacent correctness."
  - path: "@documents/skills/rust-standards/references/39_hazard_catalog_checklists.md"
    purpose: "RS-39: hazard scan checklist for regressions. CRITICAL: RSK-2408/2409 (concurrency), RSK-2406 (panic surface)."
  - path: "@documents/skills/rust-standards/references/40_time_monotonicity_determinism.md"
    purpose: "RS-40: monotonic clocks, ordering hazards, staleness detection. CRITICAL DoS: INV-2501 (Instant not SystemTime), RSK-2504 (zero-interval guards). CRITICAL TOCTOU: tick/epoch staleness."
  - path: "@documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md"
    purpose: "RS-41: fail-closed, validated construction, state machines. CRITICAL: CTR-2605 (state machines), CTR-2608 (retry backoff), RSK-2625 (unbounded channels)."

  - path: "@documents/skills/rust-standards/references/44_deterministic_simulated_testing.md"
    purpose: "RS-44: deterministic simulated testing, test isolation, and reproducibility. CRITICAL: CTR-3001 (hermetic isolation), RSK-3001 (env var mutation), RSK-3003 (sleep-based sync), CTR-3007 (simulation harnesses)."

  # Domain patterns and reference findings
  - path: "@documents/skills/rust-standards/references/27_collections_allocation_models.md"
    purpose: "RS-27: bounded collections and DoS prevention. CRITICAL: CTR-1303 (bounded stores), RSK-1302 (size math), CTR-1302 (query limits)."
  - path: "@documents/skills/rust-standards/references/32_testing_fuzz_miri_evidence.md"
    purpose: "RS-32: verification tools for DoS-prone patterns (fuzzing, property tests). CRITICAL: RSK-1703 (parser fuzzing), CTR-1701 (verification plan)."
  - path: "@documents/skills/rust-standards/references/42_pcac_ajc_integration.md"
    purpose: "RS-42: PCAC/AJC authority lifecycle (join→revalidate→consume→effect). MANDATORY for privileged handlers. CRITICAL: 7 semantic laws, reviewer checklist."
  - path: "@documents/skills/implementor-default/references/daemon-implementation-patterns.md"
    purpose: "Daemon wiring and runtime invariants that commonly regress. CRITICAL: SQL patterns (no O(N) scans), atomicity protocols."
  - path: "@documents/skills/implementor-default/references/common-review-findings.md"
    purpose: "Frequent BLOCKER/MAJOR patterns from recent PRs. CRITICAL: § 3 (unbounded DoS), § 2 (stale TOCTOU), § 6 (containment)."

decision_tree:
  entrypoint: START
  nodes[11]:
    - id: START
      purpose: "Initialize scope, collect authoritative context, and avoid ambient assumptions."
      steps[11]:
        - id: READ_REFERENCES
          action: "read all files in references. Read them yourself and don't delegate summaries to a subagent. Details matter and it's not that much reading."
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables. Replace placeholders like <TICKET_ID>, <PR_NUMBER>, and <WORKTREE_PATH> before running commands."
        - id: DISCOVER_RELEVANT_FAC_HELP
          action: |
            Discover the 4 CLI commands you will use. Run these help commands:
            (1) `apm2 fac review findings --help`
            (2) `apm2 fac push --help`
            Help output is authoritative for names/flags.
        - id: RESOLVE_SCOPE
          action: |
            Locate the ticket YAML at `documents/work/tickets/$1.yaml` and read the full file. If a PR number was provided instead, extract the ticket ID from the branch name or PR description.
            Before proceeding, read the reason field to understand each blocking relationship and note custody.responsibility_domains — DOMAIN_SECURITY or DOMAIN_AUTHN_AUTHZ trigger mandatory fail-closed review patterns.
            Orient on the ticket structure: binds links your work to requirements and evidence artifacts via file paths; scope.in_scope is your delivery contract and scope.out_of_scope is a hard boundary; definition_of_done.criteria plus linked requirement acceptance_criteria form your completion checklist.
        - id: FETCH_REVIEW_FINDINGS
          action: |
            If a PR already exists for this branch, fetch current review findings:
            `apm2 fac review findings --pr <PR_NUMBER> --json`
            This shows all BLOCKER, MAJOR, MINOR, and NIT findings from prior review rounds.
            Use these findings as your fix list — each one is a concrete issue to address.
            Orchestrator handoffs may include a doctor summary string such as
            `security=deny(2B/1M/0m/0N) code-quality=approve(0B/0M/1m/3N)`;
            treat that as triage context only, and always use the command output above
            as the authoritative full finding payload.
            Orchestrator dispatch now occurs only after all review dimensions have
            non-pending formal verdicts, so the findings set is complete and should be
            addressed in one pass across all dimensions.
            If no PR exists yet (fresh implementation), skip this step.
        - id: LOAD_REQUIRED_READING
          action: "Read any orchestrator-provided warm handoff files before edits."
        - id: LOAD_REQUIREMENT_BINDINGS
          action: |
            For each entry in binds.requirements: read the file at requirement_ref (strip the #anchor suffix). Extract the requirement's statement, acceptance_criteria, and priority. Merge these acceptance_criteria with definition_of_done.criteria to form your complete implementation checklist.

            For each entry in binds.evidence_artifacts: read the file at artifact_ref (strip the #anchor suffix). Note expected_contents — this tells you exactly what proof your PR must include (e.g., denial proofs, lifecycle receipts, test output).

            Read the parent RFC at documents/rfcs/<rfc_id>/ for design context if the requirement statements reference concepts you do not yet understand.
        - id: LIST_MODULE_AGENTS_DOCS
          action: "List module-level AGENTS docs with `rg --files -g 'AGENTS.md' crates` and record candidates for touched areas."
        - id: READ_RELEVANT_MODULE_AGENTS
          action: "Read AGENTS.md files adjacent to modules/crates that look relevant to the assigned scope."
      next: WORKTREE_PREP

    - id: WORKTREE_PREP
      purpose: "Prepare and prove a healthy worktree before code edits."
      steps[5]:
        - id: SELECT_OR_CREATE_WORKTREE
          action: "Implementor agent chooses/creates the correct worktree path and branch naming convention for the assigned scope."
        - id: MAINLINE_SYNC
          action: |
            Synchronize worktree with the local main branch. Local main is
            authoritative — do NOT treat origin/main as the source of truth.
            From your feature branch worktree run:
              git fetch origin main:main   # fast-forward local main ref
              git rebase main              # rebase feature branch onto main
            If the rebase has conflicts, resolve them before proceeding.
            Do NOT use `git pull` or `git merge origin/main` — always rebase
            onto the local main ref.
        - id: CONFLICT_ZERO_GATE
          action: "Resolve merge conflicts to zero before code changes."
        - id: WORKTREE_HEALTH_GATE
          action: "If worktree health cannot be established, stop with BLOCKED and include concrete blocker evidence."
        - id: RECORD_WORKTREE_BASELINE
          action: "Capture worktree path, branch, pre-edit base commit, and conflict status in implementation notes."
      next: PRE_EDIT_GATES

    - id: PRE_EDIT_GATES
      purpose: "Apply 5-Whys-derived guardrails before modifying code. Covers fail-closed defaults, DoS prevention, and TOCTOU atomicity."
      steps[12]:
        - id: GATE_PRODUCTION_WIRING
          action: "If adding new builders, registries, or gates, verify all production constructor paths wire them; do not rely on test-only injection."
        - id: GATE_FAIL_CLOSED_DEFAULTS
          action: "Check unknown/missing/error paths in authority/security logic; require explicit deny/failure outcome."
        - id: GATE_TRUST_VALIDATION
          action: "For signatures, digests, seals, or pointer receipts, validate authenticity and binding integrity, not just field shape."
        - id: GATE_MUTATION_ORDERING
          action: "Ensure admission checks execute before irreversible mutations unless an explicit two-phase protocol exists."
        - id: GATE_TOCTOU_ATOMICITY
          action: |
            For any code pattern matching "check → decision → act on checked state", verify that checked state cannot become stale between check and act.
            REJECT IF: permission checked then used without re-verification; quota checked then reserved non-atomically; state read outside lock then used as if valid; policy/capability read from store then applied without binding to read epoch.
            REQUIRE: atomic operations (CAS loops, atomic types, database constraints, or explicit two-phase with idempotency).
            Reference: RS-21 (atomics), RS-40 (staleness), RS-41 (state machines).
        - id: GATE_SHARED_STATE_PROTOCOLS
          action: |
            Every shared mutable state (Mutex, RwLock, Atomic*, Cell, RefCell) MUST have explicit documented synchronization protocol.
            Protocol must state: (1) what data is protected, (2) who can mutate and under what conditions, (3) lock/atomic ordering required, (4) happens-before edges, (5) async suspension invariants.
            REJECT IF: interior mutability with no synchronization comment; lock/atomic use without clear ownership; panic-in-Drop of locked guard.
            Reference: RS-21, RS-39.
        - id: GATE_ASYNC_STATE_FRESHNESS
          action: |
            Async code depending on state machine transitions or monotonic values (tick/epoch/version) MUST NOT assume stale state is valid across `.await`.
            REJECT IF: tick/epoch captured before `.await`, used after without re-validation; state machine state observed pre-await, decision made on stale assumption; leadership inferred pre-await, enforced post-await.
            REQUIRE: critical gates re-fetch fresh state immediately before enforcement; staleness checks via HLC or explicit version binding; re-validation after suspension.
            Reference: RS-40 (monotonicity), RS-21 (happens-before).
        - id: GATE_DISTRIBUTED_STATE_CONSISTENCY
          action: |
            Multi-process or multi-thread code reading from persistent storage (ledger, files, DB) MUST ensure consistency between read epoch and enforcement epoch.
            REJECT IF: ledger event read then enforced without provenance verification; file read then used without atomic/immutability proof; DB row read ignoring concurrent writers; policy cached without binding to resolver epoch; order assumptions without explicit causality.
            REQUIRE: explicit consistency mechanism (immutability, atomic DB constraint, CAS loop); proof of who can write this state; reader holds lock/version for full decision scope.
            Reference: RS-31, RS-40, RS-41.
        - id: GATE_NO_SYNTHETIC_CONSTANTS
          action: "Reject hardcoded runtime placeholders (ticks, attempts, verdicts, token counts) on production paths."
        - id: GATE_OPTIONAL_BYPASS
          action: "If gate dependencies are optional types, prove authoritative paths deny when dependency is missing and policy requires it."
        - id: GATE_HASH_PREIMAGE_FRAMING
          action: "For new commitments, include length/presence framing for variable fields and full normative-field coverage."
        - id: GATE_RESOURCE_BOUNDS
          action: |
            Every in-memory collection (Vec, HashMap, HashSet, VecDeque, BTreeMap) tracking external events or input MUST have hard MAX_* constant and eviction strategy.
            For EACH collection: (1) verify MAX_* constant exists at crate root, (2) verify overflow returns Err not truncation, (3) verify load/batch-insert enforce same cap, (4) verify concurrent writers cannot TOCTOU past cap.
            AUTOMATIC REJECT IF UNCAPPED: query result collections, persisted state reload, cache stores, event ledgers, resource pools.
            Reference: RS-27, common-review-findings.md § 3.
        - id: GATE_PANIC_SURFACE_DOS
          action: |
            Verify no untrusted input can trigger panic via unwrap(), expect(), panic!(), indexing, or division.
            For EACH unsafe/boundary path: (1) scan for panic sites, (2) confirm unreachable from untrusted input (proof required), (3) replace with fallible API (get(), checked math, Result).
            AUTOMATIC REJECT: parse().unwrap() on external input; v[index] on untrusted index; str slicing by byte offset without UTF-8 check.
            Reference: RS-15 (panic safety), RS-39 (hazards).
        - id: GATE_UNBOUNDED_LOOPS_AND_TIMEOUTS
          action: |
            Verify loops, retries, and async operations have explicit termination guarantees.
            For EACH loop/retry/spawn: (1) confirm max iteration count or break condition, (2) confirm timeout guards (Instant::elapsed < max_duration), (3) confirm exponential backoff with cap (e.g., max_delay=30s), (4) confirm circuit breaker if high failure rate.
            AUTOMATIC REJECT: loops without MAX_ITERATIONS; retry loops without backoff; spawn loops without max concurrency; requests without timeout; recursive algorithms without depth limit.
            Reference: RS-27, RS-40, RS-41.
        - id: GATE_IO_BOUNDS_AND_PARSING
          action: |
            Verify I/O reads, allocations, and parsing cannot be exploited for memory exhaustion (memory DoS).
            For EACH boundary read/parse: (1) never use .read_to_end(); use bounded loop, (2) confirm allocation size from length prefix WITH explicit cap checked BEFORE allocation, (3) confirm recursive parsing/JSON depth capped, (4) confirm string/bytes length validated before allocation.
            AUTOMATIC REJECT: r.read_to_end() without size cap; vec.reserve(len) without len < MAX check; serde_json on untrusted bytes without size validation.
            Reference: RS-31, RS-27.
        - id: GATE_E2E_COVERAGE
          action: "Require at least one test through production dispatch/runtime path for each high-risk change."
      next: IMPLEMENT

    - id: IMPLEMENT
      purpose: "Execute the minimal change set while preserving boundary contracts and preventing DoS/TOCTOU regressions."
      steps[6]:
        - id: APPLY_PATCHES
          action: |
            Implement the smallest coherent patch satisfying requirement bindings and pre-edit gates.
            If a useful abstraction, refactor, or structural improvement is necessary to meet the
            reviewer's strict quality bar, it is your responsibility to add it — do not defer
            quality-enabling refactors to a follow-up ticket.
        - id: ADD_REGRESSION_TESTS
          action: |
            Add negative and positive tests for fixed defect classes (missing state, stale state, bypass attempts, replay/order hazards, DoS, TOCTOU).

            DoS test coverage (MANDATORY for resource-touching code):
            - Collection bounds: MAX_SIZE + 1 bytes → Err not truncation; load() enforces same cap as insert()
            - Panic surface: malformed/oversized input → Err not panic; no unwrap() on untrusted data
            - Unbounded loops: loop exit after MAX_ITERATIONS; timeout after max_duration; exponential backoff with cap
            - I/O bounds: oversized protocol frame → Err before allocation; .read_to_end() never on untrusted

            TOCTOU/Race test coverage (MANDATORY for concurrent/async code):
            - Check-then-act atomicity: concurrent quota requesters, verify only one succeeds, others denied
            - State staleness: permission revoked between check and use → must deny second access
            - Async state: tick/epoch changed during await → re-validation must deny stale assumption
            - Distributed consistency: policy mutated during enforcement window → must use fresh policy not cached
        - id: VERIFY_ERROR_CHANNELS
          action: "Return structured errors for deny paths; avoid logging-and-continuing in authoritative control flow."
        - id: VERIFY_OBSERVABILITY
          action: "Ensure emitted receipts/events include enough fields to audit decisions (hashes, selectors, policy snapshot, reason codes)."
        - id: VERIFY_DOS_SURFACE
          action: |
            Before finalizing, audit the change for DoS vectors:
            - COLLECTIONS: grep Vec/HashMap/VecDeque; confirm MAX_* constant and eviction logic for each
            - PANICS: grep unwrap/expect/panic/unreachable/v[; prove each unreachable from untrusted input or replace with Result
            - LOOPS: confirm explicit MAX_ITERATIONS or break condition; timeout guards on long-running; exponential backoff with cap
            - I/O: no .read_to_end() on untrusted; allocation size checked BEFORE reserve; protocol depth/recursion capped
      next: VERIFY_WITH_FAC

    - id: VERIFY_WITH_FAC
      purpose: "Run deterministic merge-gate verification via FAC. Default mode runs gates locally using `apm2 fac gates`."
      CRITICAL_PREREQUISITE: |
        ALL changes MUST be committed before running `apm2 fac gates` in full mode or `apm2 fac push`.
        These commands WILL FAIL on a dirty working tree. Build artifacts are attested against
        the committed HEAD SHA and reused as a source of truth — uncommitted changes produce
        unattestable results. Commit first, then run gates/push.
      steps[4]:
        - id: RUN_FAC_GATES_FULL
          action: |
            COMMIT ALL CHANGES FIRST, then run `apm2 fac gates`. Full gates require a clean working tree — no uncommitted, staged, or untracked files.
            Immediately before push, run `apm2 fac gates`.
        - id: FIX_AND_RERUN
          action: |
            Fix failures, COMMIT, and re-run `apm2 fac gates` until PASS or BLOCKED.
        - id: HANDLE_BUILD_FAILURES
          action: |
            If gates fail due to build errors, check evidence logs (`apm2 fac --json logs`) for detailed output.
        - id: ESCALATE_IF_BLOCKED
          action: |
            If gate execution cannot be restored to a passing state, mark the task BLOCKED with concrete evidence and escalate.
      next: UPDATE_AGENTS_DOCS

    - id: UPDATE_AGENTS_DOCS
      purpose: "Refresh module-level AGENTS docs before push."
      steps[3]:
        - id: IDENTIFY_TOUCHED_MODULE_DOCS
          action: "Map changed code paths to nearby AGENTS.md files."
        - id: EDIT_MODULE_AGENTS_DOCS
          action: "Update relevant AGENTS.md files with new/changed module responsibilities, invariants, workflows, or guardrails introduced by the change."
        - id: NOTE_AGENTS_DOC_UPDATES
          action: "Ensure AGENTS.md edits are included in the final committed diff."
      next: COMMIT

    - id: COMMIT
      purpose: |
        MANDATORY: Stage and commit ALL work before gates or push.
        `apm2 fac gates` and `apm2 fac push` WILL FAIL on a dirty working tree.
        Build artifacts are attested against the committed HEAD SHA and reused as
        a source of truth — uncommitted changes make attestation impossible.
        There is NO workaround. Commit everything first.
      steps[2]:
        - id: STAGE_ALL_CHANGES
          action: "Run `git add -A` to stage ALL changes — implementation code, test additions, AGENTS.md updates, and any other modified files. Do NOT leave files unstaged."
        - id: CREATE_COMMIT
          action: "Run `git commit` with a concise message summarizing what changed and why. Verify with `git status` that the tree is clean (no modified, staged, or untracked files remain)."
      next: PUSH

    - id: PUSH
      purpose: "Push through FAC-only surface and handle interstitial branch/worktree failures. Requires a clean committed tree."
      steps[4]:
        - id: RUN_FAC_PUSH
          action: "`apm2 fac push` REQUIRES a clean working tree with all changes committed. It will not stage or commit for you. Run `apm2 fac push --ticket <TICKET_YAML>` (or `--branch <BRANCH>` when ticket metadata is unavailable). Expect it to take about 5-10 minutes on a fresh worktree"
        - id: CAPTURE_PR_CONTEXT
          action: "Capture PR number/URL from `apm2 fac push` output for monitoring and restart."
        - id: HANDLE_PUSH_FAILURE
          action: "If push fails (for example non-fast-forward or unresolved conflict), return to WORKTREE_PREP, repair, then retry push."
        - id: SINGLE_PUSH_PATH
          action: "Do not run raw `git push`/manual review dispatch in this workflow."
      next: EMIT_RESULT

    - id: EMIT_RESULT
      purpose: "Finalize only after verifiable facts are present in FAC artifacts."
      steps[1]:
        - id: VERIFY_FACT_PERSISTENCE
          action: "Ensure FAC command artifacts and diff-backed evidence are present; do not add narrative explanations."
      next: STOP

    - id: STOP
      purpose: "Terminate."
      steps[1]:
        - id: DONE
          action: "output DONE and nothing else, your task is complete."

invariants[17]:
  # Clean Tree Invariant (HIGHEST PRIORITY — agents repeatedly violate this)
  - "NEVER run `apm2 fac gates` or `apm2 fac push` with uncommitted changes. ALL files — code, tests, docs, tickets — MUST be committed first. Build artifacts are SHA-attested and reused as a source of truth; a dirty tree makes attestation impossible and the commands WILL FAIL."

  # No Backwards Compatibility by Default
  - "Backwards compatibility is expressly and intentionally NEVER required unless specifically called out as a requirement in a work object. Do not add deprecated shims, re-exports, renamed aliases, or any other backwards-compat scaffolding by default. Breaking changes are the norm; migration paths are only required when a ticket or RFC explicitly mandates them."

  - "Do not ship fail-open defaults for missing, stale, unknown, or unverifiable authority/security state."
  - "Do not rely on shape-only validation for trust decisions; validate authenticity and binding claims."
  - "Do not mutate durable or single-use state before all deny gates that can reject the operation."
  - "Do not hardcode synthetic operational values (ticks, counters, tokens, verdicts) in production paths."
  - "Do not treat optional guard dependencies as permissive bypasses in authoritative paths."
  - "Do not claim completion from unit tests alone when production wiring paths are untested."
  - "Do not claim hash/integrity guarantees without framed preimage and full-field coverage."
  - "Persist verifiable command and diff evidence in FAC artifacts; do not rely on narrative explanations."
  - "If a safety-critical requirement cannot be implemented safely in scope, stop and preserve blocker evidence in FAC artifacts."

  # DoS Prevention Invariants
  - "Every in-memory collection tracking unbounded external state MUST have hard MAX_* limits enforced on ALL write/load paths; overflow returns Err not truncation."
  - "Untrusted input cannot cause panic (parse/index/unwrap/division); use Result types for all fallible operations at boundaries."
  - "Loops, retries, and recursive algorithms MUST have explicit iteration/depth/time bounds; no indefinite spinning or exponential algorithms without cap."
  - "I/O reads MUST be bounded by explicit size caps BEFORE allocation; never use unbounded .read_to_end() on untrusted streams."
  - "Timeout logic uses monotonic Instant not wall-clock SystemTime; duration_since() uses checked_* variant; intervals guarded for zero before division."

  # Deterministic Test Invariant
  - "Tests MUST be deterministic and hermetically isolated: inject all external dependencies (time, I/O, randomness, environment) via traits or parameters; never share mutable process-global state between tests; never use sleep-based synchronization; never depend on HashMap iteration order, filesystem state, or network availability. Reference: RS-44 (deterministic simulated testing)."

  # TOCTOU Prevention Invariants
  - "If state machine state (tick, epoch, version, cursor) is read outside a lock, re-validate before enforcement; do not assume stale reads are truthful across await."
  - "Cross-process reads from persistent storage (ledger, files, DB) require explicit provenance checks (signatures, version bindings, immutability proofs); do not assume read state is authoritative."
  - "Non-atomic check-then-act sequences (quota reservation, resource allocation, permission enforcement) require atomic operations (CAS loops, atomic types, database constraints) or explicit idempotent two-phase."
  - "Shared mutable state using interior mutability without an explicit documented synchronization protocol is a BLOCKER-level finding; every Mutex/RwLock/Atomic must have happens-before comment."
