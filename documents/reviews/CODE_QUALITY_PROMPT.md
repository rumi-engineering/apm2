title: Code Quality Review Prompt
protocol:
  id: CODE-QUALITY-REVIEW
  version: 1.2.0
  type: executable_specification
  inputs[1]:
    - PR_URL
  outputs[2]:
    - PRComment
    - StatusCheck

variables:
  PR_URL: "$PR_URL"

references[39]:
  - path: "@documents/theory/glossary/glossary.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: "@documents/skills/modes-of-reasoning/assets/07-type-theoretic.json"
    purpose: "Mode #07: Type-Theoretic Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/40-mechanistic.json"
    purpose: "Mode #40: Mechanistic Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/13-abductive.json"
    purpose: "Mode #13: Abductive Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/17-simplicity-compression.json"
    purpose: "Mode #17: Simplicity / Compression Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/59-dialectical.json"
    purpose: "Mode #59: Dialectical Reasoning"
  - path: "@AGENTS.md"
    purpose: "Global Agent Instructions"
  - path: "@documents/security/SECURITY_POLICY.cac.json"
    purpose: "Security Policy"
  - path: "@documents/theory/unified_theory.json"
    purpose: "Holonic Unified Theory"
  - path: "@documents/skills/rust-standards/SKILL.md"
    purpose: "Rust Standards Skill"
  - path: "@documents/skills/rust-standards/references/00_operating_mode.md"
    purpose: "RS-00: Operating Mode"
  - path: "@documents/skills/rust-standards/references/02_inputs_and_stop_conditions.md"
    purpose: "RS-02: Inputs & Stop Conditions"
  - path: "@documents/skills/rust-standards/references/04_qcp_classification.md"
    purpose: "RS-04: QCP Classification"
  - path: "@documents/skills/rust-standards/references/06_triage_fast_scan.md"
    purpose: "RS-06: Triage Fast Scan"
  - path: "@documents/skills/rust-standards/references/08_invariant_mapping.md"
    purpose: "RS-08: Invariant Mapping"
  - path: "@documents/skills/rust-standards/references/10_abstraction_and_simplification.md"
    purpose: "RS-10: Abstraction & Simplification"
  - path: "@documents/skills/rust-standards/references/12_rust_soundness_and_unsafe.md"
    purpose: "RS-12: Soundness & Unsafe"
  - path: "@documents/skills/rust-standards/references/14_allocator_arena_pool_review.md"
    purpose: "RS-14: Allocators & Pools"
  - path: "@documents/skills/rust-standards/references/16_error_handling_and_panic_policy.md"
    purpose: "RS-16: Error & Panic Policy"
  - path: "@documents/skills/rust-standards/references/18_api_design_and_semver.md"
    purpose: "RS-18: API Design & Semver"
  - path: "@documents/skills/rust-standards/references/20_testing_evidence_and_ci.md"
    purpose: "RS-20: Testing & CI"
  - path: "@documents/skills/rust-standards/references/22_performance_review.md"
    purpose: "RS-22: Performance Review"
  - path: "@documents/skills/rust-standards/references/24_dependency_and_build_surface.md"
    purpose: "RS-24: Dependencies & Build"
  - path: "@documents/skills/rust-standards/references/26_severity_and_verdict.md"
    purpose: "RS-26: Severity & Verdict"
  - path: "@documents/skills/rust-standards/references/28_required_actions_templates.md"
    purpose: "RS-28: Required Actions Templates"
  - path: "@documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md"
    purpose: "RS-41: Safe Patterns"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-01: Loop Closure"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-02: Context Sufficiency"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-03: Monotone Ledger"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-05: Dual-Axis Containment"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-06: MDL Budget"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-07: Verifiable Summaries"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-08: Goodhart Resistance"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-12: Bounded Search"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-13: Semantic Typing"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-15: Content-Addressed Evidence"
  - path: "@documents/rfcs/RFC-0019/AUTONOMOUS_FORGE_ADMISSION_CYCLE.md"
    purpose: "RFC-0019: Autonomous Forge Admission Cycle"
  - path: "@.github/review-gate/trusted-reviewers.json"
    purpose: "Authoritative allowlist for machine-readable reviewer_id and GitHub identity binding."
  - path: "@documents/reviews/REVIEW_GATE_WAIVER_FLOW.md"
    purpose: "Waiver-only operator override flow for blocked review gates."

decision_tree:
  entrypoint: PHASE_1_COLLECT_PR_IDENTITY
  nodes[7]:
    - id: PHASE_1_COLLECT_PR_IDENTITY
      purpose: "Gather PR metadata, diff, and ticket bindings."
      steps[6]:
        - id: FETCH_PR_METADATA
          action: command
          run: "gh pr view $PR_URL --json number,title,body,author,baseRefName,headRefName,headRefOid,commits,files,additions,deletions"
          capture_as: pr_metadata_json
        - id: EXTRACT_PR_FIELDS
          action: parse_json
          from: pr_metadata_json
          extract: [pr_number, pr_title, pr_body, files, additions, deletions, headRefName, baseRefName, headRefOid]
        - id: ASSIGN_REVIEWED_SHA
          action: "Set reviewed_sha = headRefOid."
        - id: STOP_IF_NO_REVIEWED_SHA
          if: "reviewed_sha is empty"
          then:
            action: "EMIT StopCondition STOP-NO-HEAD-SHA severity BLOCKER message 'Could not resolve latest commit SHA from PR_URL'."
            stop: true
        - id: FETCH_DIFF
          action: command
          run: "gh pr diff $PR_URL"
          capture_as: diff_content
        - id: EXTRACT_TICKET_BINDING
          action: parse_text
          from_fields: [pr_title, pr_body]
          patterns:
            ticket_id: "TCK-[0-9]{5}"
            rfc_id: "RFC-[0-9]{4}"
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
            If review_worktree exists: use it as primary local source for file reads and adjacent context.
            If review_worktree does not exist: continue with PR API/diff review mode.
            Do NOT create a new worktree by default during review execution.
      next: PHASE_2_GATHER_TICKET_CONTEXT

    - id: PHASE_2_GATHER_TICKET_CONTEXT
      purpose: "Map PR to design intent and DOD."
      decisions[5]:
        - id: HANDLE_MISSING_TICKET
          if: "ticket_id is empty"
          then:
            action: "EMIT StopCondition STOP-NO-BINDING severity BLOCKER message 'Non-trivial changes require binding ticket'."
        - id: READ_RFC_CONTEXT
          if: "rfc_id is found"
          actions: ["Read decomposition and design decisions for RFC."]
        - id: READ_TICKET_CONTEXT
          if: "ticket_id is found"
          actions: ["Read ticket metadata and body."]
      next: PHASE_3_ANALYZE_FILES

    - id: PHASE_3_ANALYZE_FILES
      purpose: "Perform static analysis on changed and adjacent files."
      steps[2]:
        - id: REVIEW_MODIFIED_FILES
          action: for_each_file
          cases:
            - match: "*.rs"
              action: "Read entire file."
            - match: "config files"
              action: "Verify syntax and correctness."
            - match: "docs"
              action: "Verify accuracy against code."
        - id: READ_ADJACENT_CONTEXT
          action: "Read mod.rs, related tests, and AGENTS.md in touched modules."
      next: PHASE_4_EXECUTE_REVIEW

    - id: PHASE_4_EXECUTE_REVIEW
      purpose: "Apply Rust standards and architectural lenses."
      lenses[7]:
        - lens: "Rust Soundness"
          focus: "Ownership, lifetimes, unsafe justification."
        - lens: "Failure Models"
          focus: "Error propagation, observability, stable identities."
        - lens: "Testing Evidence"
          focus: "Coverage, negative evidence, falsification."
        - lens: "Documentation"
          focus: "Public APIs, AGENTS.md accuracy."
        - lens: "Performance"
          focus: "Allocations, hot paths, algorithmic risk."
        - lens: "Security"
          focus: "SCP determination, boundary scrutiny."
        - lens: "Architectural Alignment"
          focus: "Holonic boundary model, Markov Blanket."
      next: PHASE_5_COMPUTE_VERDICT

    - id: PHASE_5_COMPUTE_VERDICT
      purpose: "Assign PASS/FAIL based on findings severity."
      severity_definitions:
        BLOCKER: "Unsound code, security vulnerability, data loss, scope missing."
        MAJOR: "Missing tests, API issues, criteria not met."
        MINOR: "Non-idiomatic, missing docs."
        NIT: "Style, optional improvements."
      verdict_rules:
        PASS: "blocker_count == 0 AND major_count == 0"
        FAIL: "blocker_count > 0 OR major_count > 0"
      next: PHASE_6_PUBLISH_RESULTS

    - id: PHASE_6_PUBLISH_RESULTS
      purpose: "Post PR comment and update status checks."
      comment_content:
        structure:
          - section: "Verdict Banner"
            format: "## Code Quality Review: PASS | FAIL"
            content: "Clear verdict with overall severity summary"
          - section: "Summary"
            content: "1-2 paragraph overview of what was reviewed and key conclusions"
          - section: "Worktree Resolution"
            content: "State reused worktree path (or no-existing-worktree fallback mode) and branch match basis."
          - section: "Ticket Requirements"
            content: "Enumerated list of DOD criteria from bound ticket"
          - section: "Requirements Verification"
            content: "For each requirement: evidence of how the code satisfies it"
          - section: "Quality Analysis"
            subsections:
              - "Simplicity: Minimal moving parts, no unnecessary abstraction"
              - "Elegance: Idiomatic patterns, clean data flow"
              - "Invariant Adherence: Conformance to Rust Standards references"
          - section: "Lenses Applied"
            content: "Summary of each lens from PHASE_4 and what was checked"
          - section: "BLOCKER FINDINGS"
            format: "### **BLOCKER FINDINGS**"
            content: "Numbered list of blockers, each with:"
            item_structure:
              - "Issue: What is wrong"
              - "Impact: What breaks or is at risk"
              - "Consequence: Downstream effects if unaddressed"
              - "Required Fix: Clear, actionable remediation"
          - section: "MAJOR FINDINGS"
            format: "### **MAJOR FINDINGS**"
            content: "Numbered list of majors with same structure as blockers"
          - section: "MINOR/NIT FINDINGS"
            format: "### **MINOR FINDINGS** / ### **NITS**"
            content: "Optional sections for lower-severity items"
          - section: "POSITIVE OBSERVATIONS"
            format: "### **POSITIVE OBSERVATIONS (PASS)**"
            content: "What the PR does well; specific invariants correctly upheld"
          - section: "Machine-Readable Metadata (REQUIRED)"
            content: "Append this exact metadata block at the end of the comment for gate evaluation."
            template: |
              <!-- apm2-review-metadata:v1:code-quality -->
              ```json
              {
                "schema": "apm2.review.metadata.v1",
                "review_type": "code-quality",
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
              - "reviewer_id MUST appear in `.github/review-gate/trusted-reviewers.json` under `code_quality`."
              - "Missing/invalid metadata is gate-fatal."
          - section: "Footer"
            format: "---"
            content: "Reviewed commit: $reviewed_sha (resolved from PR_URL at review start for auditability)"
      steps[4]:
        - id: WRITE_FINDINGS
          action: write_file
          path: "quality_findings.md"
          content: "$FORMATTED_FINDINGS"
        - id: APPEND_METADATA
          action: append_file
          path: "quality_findings.md"
          content: "$MACHINE_READABLE_METADATA_BLOCK"
        - id: POST_AND_UPDATE
          action: command
          note: |
            code-quality sets its own category status via the GitHub
            statuses API because the xtask review-exec command is
            security-category only (it hardcodes the security review
            context, not code-quality).
          run: |
            gh pr comment $PR_URL --body-file quality_findings.md
            if [ "$VERDICT_STATE" == "success" ]; then
              gh api --method POST "/repos/{owner}/{repo}/statuses/$reviewed_sha" \
                -f state="success" \
                -f context="ai-review/code-quality" \
                -f description="Code quality review passed"
            else
              gh api --method POST "/repos/{owner}/{repo}/statuses/$reviewed_sha" \
                -f state="failure" \
                -f context="ai-review/code-quality" \
                -f description="Code quality review found issues - see PR comments"
            fi
            rm quality_findings.md
        - id: TERMINATE
          action: output
          content: "DONE"
