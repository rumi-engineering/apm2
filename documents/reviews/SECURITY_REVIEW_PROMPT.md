title: Security Review Prompt
protocol:
  id: SECURITY-REVIEW
  version: 2.2.0
  type: executable_specification
  inputs[1]:
    - PR_URL
  outputs[2]:
    - PRComment
    - StatusCheck

variables:
  PR_URL: "$PR_URL"

references[42]:
  - path: "@documents/skills/modes-of-reasoning/assets/79-adversarial-red-team.json"
    purpose: "Mode #79: Adversarial / Red-Team Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/08-counterexample-guided.json"
    purpose: "Mode #08: Counterexample-Guided Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/49-robust-worst-case.json"
    purpose: "Mode #49: Robust / Worst-Case Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/55-game-theoretic-strategic.json"
    purpose: "Mode #55: Game-Theoretic Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/36-assurance-case.json"
    purpose: "Mode #36: Assurance-Case Reasoning"
  - path: "@documents/security/SECURITY_POLICY.cac.json"
    purpose: "Security Policy"
  - path: "@documents/security/THREAT_MODEL.cac.json"
    purpose: "Threat Model"
  - path: "@documents/security/SECRETS_MANAGEMENT.cac.json"
    purpose: "Secrets Management"
  - path: "@documents/security/NETWORK_DEFENSE.cac.json"
    purpose: "Network Threat Matrix"
  - path: "@documents/skills/rust-standards/SKILL.md"
    purpose: "Rust Standards"
  - path: "@documents/skills/rust-standards/references/00_operating_mode.md"
    purpose: "RS-00: Operating Mode"
  - path: "@documents/skills/rust-standards/references/02_inputs_and_stop_conditions.md"
    purpose: "RS-02: Inputs & Stop Conditions"
  - path: "@documents/skills/rust-standards/references/06_triage_fast_scan.md"
    purpose: "RS-06: Triage Fast Scan"
  - path: "@documents/skills/rust-standards/references/08_invariant_mapping.md"
    purpose: "RS-08: Invariant Mapping"
  - path: "@documents/skills/rust-standards/references/12_rust_soundness_and_unsafe.md"
    purpose: "RS-12: Soundness & Unsafe"
  - path: "@documents/skills/rust-standards/references/14_allocator_arena_pool_review.md"
    purpose: "RS-14: Allocators & Pools"
  - path: "@documents/skills/rust-standards/references/16_error_handling_and_panic_policy.md"
    purpose: "RS-16: Error & Panic Policy"
  - path: "@documents/skills/rust-standards/references/19_unsafe_rust_obligations.md"
    purpose: "RS-19: Unsafe Obligations"
  - path: "@documents/skills/rust-standards/references/20_testing_evidence_and_ci.md"
    purpose: "RS-20: Testing & CI"
  - path: "@documents/skills/rust-standards/references/21_concurrency_atomics_memory_order.md"
    purpose: "RS-21: Concurrency & Atomics"
  - path: "@documents/skills/rust-standards/references/23_async_pin_cancellation.md"
    purpose: "RS-23: Async & Cancellation"
  - path: "@documents/skills/rust-standards/references/24_dependency_and_build_surface.md"
    purpose: "RS-24: Dependencies & Build"
  - path: "@documents/skills/rust-standards/references/26_severity_and_verdict.md"
    purpose: "RS-26: Severity & Verdict"
  - path: "@documents/skills/rust-standards/references/30_paths_filesystem_os.md"
    purpose: "RS-30: Paths & Filesystem"
  - path: "@documents/skills/rust-standards/references/31_io_protocol_boundaries.md"
    purpose: "RS-31: I/O & Protocol Boundaries"
  - path: "@documents/skills/rust-standards/references/34_security_adjacent_rust.md"
    purpose: "RS-34: Security-Adjacent Rust"
  - path: "@documents/skills/rust-standards/references/39_hazard_catalog_checklists.md"
    purpose: "RS-39: Hazard Catalog"
  - path: "@documents/skills/rust-standards/references/40_time_monotonicity_determinism.md"
    purpose: "RS-40: Time & Monotonicity"
  - path: "@documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md"
    purpose: "RS-41: Safe Patterns"
  - path: "@documents/skills/rust-standards/references/42_distributed_security_invariants.md"
    purpose: "RS-42: Distributed Invariants"
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "LAW-03: Monotone Ledger"
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "LAW-05: Dual-Axis Containment"
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "LAW-06: MDL as a Gated Budget"
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "LAW-07: Verifiable Summaries"
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "LAW-08: Goodhart Resistance"
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "LAW-09: Temporal Pinning & Freshness"
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "LAW-11: Idempotent Actuation"
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "LAW-12: Bounded Search and Termination"
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "LAW-14: Risk-Weighted Evidence"
  - path: "@.github/review-gate/trusted-reviewers.json"
    purpose: "Authoritative allowlist for machine-readable reviewer_id and GitHub identity binding."
  - path: "@documents/reviews/REVIEW_GATE_WAIVER_FLOW.md"
    purpose: "Waiver-only operator override flow for blocked review gates."

decision_tree:
  entrypoint: PHASE_1_COLLECT_PR_IDENTITY
  nodes[8]:
    - id: PHASE_1_COLLECT_PR_IDENTITY
      purpose: "Gather PR metadata, diff, and ticket/RFC bindings."
      steps[7]:
        - id: FETCH_PR_METADATA
          action: command
          run: "gh pr view $PR_URL --json number,title,body,baseRefName,headRefName,headRefOid,files"
          capture_as: pr_metadata_json
        - id: FETCH_DIFF
          action: command
          run: "gh pr diff $PR_URL"
          capture_as: diff_content
        - id: EXTRACT_PR_BRANCHES_AND_HEAD
          action: parse_json
          from: pr_metadata_json
          extract: [headRefName, baseRefName, headRefOid]
        - id: ASSIGN_REVIEWED_SHA
          action: "Set reviewed_sha = headRefOid."
        - id: STOP_IF_NO_REVIEWED_SHA
          if: "reviewed_sha is empty"
          then:
            action: "EMIT StopCondition STOP-NO-HEAD-SHA severity BLOCK message 'Could not resolve latest commit SHA from PR_URL'."
            stop: true
        - id: EXTRACT_BINDINGS
          action: parse_text
          from_fields: [pr_metadata_json, diff_content]
          patterns:
            ticket_id: "TCK-[0-9]{5}"
            rfc_id: "RFC-[0-9]{4}"
            waiver_id: "WVR-[0-9]{4}"
        - id: STOP_IF_NO_BINDING
          if: "ticket_id is empty AND rfc_id is empty"
          then:
            action: "EMIT StopCondition STOP-NO-BINDING severity BLOCK message 'Security review requires binding ticket/RFC'."
            stop: true
      next: PHASE_1A_RESOLVE_WORKTREE

    - id: PHASE_1A_RESOLVE_WORKTREE
      purpose: "Resolve an existing local worktree for this PR. Default is reuse, never auto-create."
      steps[4]:
        - id: LIST_WORKTREES
          action: command
          run: "git worktree list --porcelain | awk '/^worktree /{wt=$2}/^branch /{b=$2; sub(/^refs\\/heads\\//,\"\",b); print wt \"\\t\" b}'"
          capture_as: worktree_index
        - id: MATCH_BY_HEAD_BRANCH
          action: select_first
          from: worktree_index
          where: "branch == headRefName"
          capture_as: review_worktree
        - id: FALLBACK_MATCH_BY_TICKET
          if: "review_worktree is empty AND ticket_id is not empty"
          action: "Select first entry where branch contains ticket_id OR path contains ticket_id."
        - id: ENFORCE_DEFAULT_REUSE_POLICY
          action: |
            If review_worktree exists: use it as the local source of truth for file reads.
            If review_worktree does not exist: continue with PR API/diff review mode.
            Do NOT create a new worktree by default during review execution.
      next: PHASE_2_SCP_DETERMINATION

    - id: PHASE_2_SCP_DETERMINATION
      purpose: "Determine if the PR touches the Security-Critical Path (SCP)."
      scp_areas[5]:
        - id: CRYPTO
          match_path: ["**/crypto/**", "**/keys/**", "**/signing/**"]
          match_symbols: ["ed25519", "blake3", "canonical", "hash"]
        - id: NETWORK_IPC
          match_path: ["**/proto/**", "**/rpc/**", "**/net/**"]
          match_symbols: ["TcpStream", "UnixStream", "zbus", "prost"]
        - id: LEDGER_PERSISTENCE
          match_path: ["**/ledger/**", "**/persistence/**", "**/evidence/**"]
          match_symbols: ["append_only", "history", "replay", "cursor"]
        - id: TOOL_EXEC
          match_path: ["**/exec/**", "**/spawn/**"]
          match_symbols: ["Command::new", "std::process"]
        - id: POLICY_GATES
          match_path: ["documents/security/**", "SECURITY.md", "**/ci/**", ".github/workflows/**"]
      steps[1]:
        - id: COMPUTE_SCP
          action: "Set SCP = YES if any area matches; else NO."
      next: PHASE_3_MARKOV_BLANKET

    - id: PHASE_3_MARKOV_BLANKET
      purpose: "Map inputs, validation, and side effects for every touched boundary."
      steps[1]:
        - id: MAP_BOUNDARIES
          action: for_each_boundary_touched
          identify: [Inputs, Validation, Outputs, FailureBehavior, Limits]
          requirement: "IF validation OR limits are missing for untrusted input -> severity HIGH."
      next: PHASE_4_EXECUTE_AUDIT

    - id: PHASE_4_EXECUTE_AUDIT
      purpose: "Apply domain-specific security modules and textbook chapters."
      force_multiplier_strategies[6]:
        - lens: "Holonic Blast Radius Analysis"
          strategy: "Map compromise propagation paths across holon boundaries."
          reasoning: [55, 49]
        - lens: "Audit the 'Invisible Contract'"
          strategy: "Search for missing economic costs or resource caps."
          reasoning: [49]
        - lens: "Treat Protocol as Code"
          strategy: "Game protocol logic for downgrade attacks or canonicalization ambiguity."
          reasoning: [55]
        - lens: "Search for 'Entropy Leaks'"
          strategy: "Find sequences of partial failures that bypass gates."
          reasoning: [8]
        - lens: "Demand 'Negative Evidence'"
          strategy: "Reject parsers unless they include stress-test corpora."
          reasoning: [8]
        - lens: "The 'Assurance Case' Mindset"
          strategy: "Construct Claim-Argument-Evidence justification."
          reasoning: [36]
      audit_categories[6]:
        - category: "Identity, Cryptography, and Wire Semantics"
          focus: "Signing, verification, hashing, and deterministic representation."
        - category: "Network and IPC Boundaries"
          focus: "Parsing untrusted data, framing, and DoS mitigation."
        - category: "Filesystem and Process Boundaries"
          focus: "Path traversal, temp files, shell injection, and permissions."
        - category: "Ledger and Evidence Integrity"
          focus: "Append-only persistence, crash recovery, and history verification."
        - category: "Memory Safety and Soundness"
          focus: "Unsafe code, async cancellation safety, and resource exhaustion."
        - category: "Gate, Policy, and Supply Chain"
          focus: "Changes to security docs, CI gates, and new dependencies."
      steps[2]:
        - id: RUN_AUDIT
          action: "Identify applicable categories based on SCP determination and Markov blanket. Apply paired references to the diff."
        - id: APPLY_FORCE_MULTIPLIERS
          action: "Apply the Advanced Reasoning Lenses to find deep architectural and protocol defects."
      next: PHASE_5_GATE_POLICY_AUDIT

    - id: PHASE_5_GATE_POLICY_AUDIT
      purpose: "Audit changes to security documentation and enforcement gates."
      if: "area == POLICY_GATES"
      steps[1]:
        - id: CLASSIFY_POLICY_CHANGE
          action: classify
          options[3]:
            - id: STRICTNESS_DECREASE
              rule: |
                BLOCK unless valid, unexpired WVR-#### exists and is referenced.

                Waiver validation:
                - `waiver.references.commit_sha` MUST equal reviewed_sha; OR
                - If the PR head includes a waiver-only commit that only changes
                  `documents/work/waivers/`, `commit_sha` MAY equal the immediate
                  parent of reviewed_sha (pre-waiver PR head).
            - id: STRICTNESS_INCREASE
              rule: "BLOCK unless bound RFC exists describing implementation as deterministic checks."
            - id: CLARIFICATION
              rule: "Allowed if precision is maintained."
      next: PHASE_6_COMPUTE_VERDICT

    - id: PHASE_6_COMPUTE_VERDICT
      purpose: "Assign final verdict and severity using Assurance-Case reasoning."
      rules:
        BLOCK: "any finding that violates security invariants or lacks sufficient evidence of safety."
        RE-AUDIT: "MANDATORY if SCP == YES and changes were made."
      steps[1]:
        - id: CONSTRUCT_ASSURANCE_CASE
          action: "Construct a Claim-Argument-Evidence structure for each finding and the final verdict."
      next: PHASE_7_EXECUTE_ACTIONS

    - id: PHASE_7_EXECUTE_ACTIONS
      purpose: "Post findings (Assurance-Case format) to PR and update status check."
      comment_content:
        structure:
          - section: "Verdict Banner"
            format: "## Security Review: PASS | FAIL"
            content: "Clear verdict with SCP determination and severity summary"
          - section: "Summary"
            content: "1-2 paragraph overview of security scope and key conclusions"
          - section: "Worktree Resolution"
            content: "State reused worktree path (or no-existing-worktree fallback mode) and branch match basis."
          - section: "SCP Determination"
            content: "Which security-critical areas were touched and why"
          - section: "Markov Blanket Analysis"
            content: "Input/validation/output mapping for each boundary"
          - section: "BLOCKER FINDINGS"
            format: "### **BLOCKER FINDINGS**"
            content: "Numbered list of blockers, each with:"
            item_structure:
              - "Issue: What security invariant is violated"
              - "Impact: Attack surface or vulnerability exposed"
              - "Consequence: Blast radius if exploited"
              - "Required Fix: Clear, actionable remediation"
          - section: "MAJOR FINDINGS"
            format: "### **MAJOR FINDINGS**"
            content: "Numbered list of majors with same structure as blockers"
          - section: "POSITIVE OBSERVATIONS"
            format: "### **POSITIVE OBSERVATIONS (PASS)**"
            content: "Security invariants correctly upheld; defense-in-depth wins"
          - section: "Machine-Readable Metadata (Auto-Generated)"
            content: |
              Do not hand-author the metadata block.
              Post only the human-readable findings comment.
              FAC sync autogenerates and patches the machine-readable metadata
              (`schema`, `review_type`, `pr_number`, `head_sha`, `verdict`,
              `severity_counts`, `reviewer_id`) onto the comment.
            template: |
              <!-- apm2-review-metadata:v1:security -->
              ```json
              {
                "schema": "apm2.review.metadata.v1",
                "review_type": "security",
                "pr_number": <pr_number>,
                "head_sha": "$reviewed_sha",
                "verdict": "PASS|FAIL",
                "severity_counts": {
                  "blocker": <blocker_count>,
                  "major": <major_count>,
                  "minor": <minor_count>,
                  "nit": <nit_count>
                },
                "reviewer_id": "<allowlisted_reviewer_id>"
              }
              ```
            constraints:
              - "head_sha MUST equal reviewed_sha exactly."
              - "pr_number MUST equal the PR being reviewed."
              - "reviewer_id MUST appear in `.github/review-gate/trusted-reviewers.json` under `security`."
              - "Missing/invalid metadata is gate-fatal."
          - section: "Assurance Case"
            content: "Claim-Argument-Evidence structure for final verdict"
          - section: "Footer"
            format: "---"
            content: "Reviewed commit: $reviewed_sha (resolved from PR_URL at review start for auditability)"
      steps[4]:
        - id: WRITE_FINDINGS
          action: write_file
          path: "security_findings.md"
          content: "$FINDINGS_ASSURANCE_CASE"
        - id: APPEND_METADATA
          action: "No-op. Metadata is generated by FAC sync after comment post."
        - id: POST_AND_UPDATE
          action: command
          note: |
            Post findings as a PR comment only.
            Do NOT call GitHub statuses/check-runs APIs directly.
            The authoritative `Review Gate Success` status is produced by
            the review-gate evaluator from FAC-generated machine-readable
            metadata synced onto your comment.
          run: |
            gh pr comment $PR_URL --body-file security_findings.md
            rm security_findings.md
        - id: TERMINATE
          action: output
          content: "DONE"
