title: Code Quality Review Prompt
protocol:
  id: CODE-QUALITY-REVIEW
  version: 1.0.0
  type: executable_specification
  inputs[2]:
    - PR_URL
    - HEAD_SHA
  outputs[2]:
    - PRComment
    - StatusCheck

variables:
  PR_URL: "$PR_URL"
  HEAD_SHA: "$HEAD_SHA"

reviewer_rules[5]:
  - id: REQUIREMENTS_GATE
    rule: "Verify every stated requirement (ticket/RFC acceptance criteria, PR description, and diff-intent) is fully satisfied to rust-standards' bar; missing/partial requirements are BLOCKER or MAJOR."
  - id: RUST_STANDARDS_PRIMARY
    rule: "Apply rust-standards as the primary acceptance bar; do not dilute findings with cosmetic issues."
  - id: IGNORE_INFRA_NITS
    rule: "Do NOT report CI failures, formatting, clippy/lints, or other minor infractions; treat style-only or lint-only issues as out-of-scope."
  - id: SHA_IN_COMMENT
    rule: "Every PRComment MUST include a line: 'Reviewed commit: $HEAD_SHA'."
  - id: ALWAYS_COMMENT
    rule: "A PR comment is ALWAYS required, regardless of PASS/FAIL."

references[35]:
  - path: "@documents/skills/modes-of-reasoning/artifacts/07-type-theoretic.json"
    purpose: "Mode #07: Type-Theoretic Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/40-mechanistic.json"
    purpose: "Mode #40: Mechanistic Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/13-abductive.json"
    purpose: "Mode #13: Abductive Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/17-simplicity-compression.json"
    purpose: "Mode #17: Simplicity / Compression Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/59-dialectical.json"
    purpose: "Mode #59: Dialectical Reasoning"
  - path: "@AGENTS.md"
    purpose: "Global Agent Instructions"
  - path: "@documents/security/SECURITY_POLICY.md"
    purpose: "Security Policy"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/unified-theory.md"
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
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_01.md"
    purpose: "LAW-01: Loop Closure"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_02.md"
    purpose: "LAW-02: Context Sufficiency"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_03.md"
    purpose: "LAW-03: Monotone Ledger"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_05.md"
    purpose: "LAW-05: Dual-Axis Containment"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_06.md"
    purpose: "LAW-06: MDL Budget"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_07.md"
    purpose: "LAW-07: Verifiable Summaries"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_08.md"
    purpose: "LAW-08: Goodhart Resistance"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_12.md"
    purpose: "LAW-12: Bounded Search"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_13.md"
    purpose: "LAW-13: Semantic Typing"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_15.md"
    purpose: "LAW-15: Content-Addressed Evidence"

decision_tree:
  entrypoint: PHASE_1_COLLECT_PR_IDENTITY
  nodes[6]:
    - id: PHASE_1_COLLECT_PR_IDENTITY
      purpose: "Gather PR metadata, diff, and ticket bindings."
      steps[4]:
        - id: FETCH_PR_METADATA
          action: command
          run: "gh pr view $PR_URL --json number,title,body,author,baseRefName,headRefName,commits,files,additions,deletions"
          capture_as: pr_metadata_json
        - id: EXTRACT_PR_FIELDS
          action: parse_json
          from: pr_metadata_json
          extract: [pr_number, pr_title, pr_body, files, additions, deletions]
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
      next: PHASE_2_GATHER_TICKET_CONTEXT

    - id: PHASE_2_GATHER_TICKET_CONTEXT
      purpose: "Map PR to design intent and DOD."
      decisions[5]:
        - id: HANDLE_MISSING_TICKET
          if: "ticket_id is empty"
          then:
            action: "EMIT StopCondition STOP-NO-BINDING severity BLOCKER message 'Non-trivial changes require binding ticket'; record as BLOCKER finding and continue to publish results (do not halt execution)."
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
        MINOR: "Out-of-scope for this review; DO NOT report."
        NIT: "Out-of-scope for this review; DO NOT report."
      verdict_rules:
        PASS: "blocker_count == 0 AND major_count == 0"
        FAIL: "blocker_count > 0 OR major_count > 0"
      next: PHASE_6_PUBLISH_RESULTS

    - id: PHASE_6_PUBLISH_RESULTS
      purpose: "Post PR comment and update status checks."
      steps[3]:
        - id: WRITE_FINDINGS
          action: write_file
          path: "quality_findings.md"
          content: "Reviewed commit: $HEAD_SHA\n\n$FORMATTED_FINDINGS"
        - id: POST_COMMENT
          action: command
          run: "gh pr comment $PR_URL --body-file quality_findings.md"
        - id: UPDATE_STATUS
          action: command
          run: |
            # If PASS, update status. If FAIL, the reviewer should post findings manually or via a future exec tool.
            # For now, we consolidate to avoid double-posting during automated runs.
            gh api --method POST "/repos/{owner}/{repo}/statuses/$HEAD_SHA" -f state="$VERDICT_STATE" -f context="ai-review/code-quality" -f description="Code quality review $VERDICT_STATE"
            rm quality_findings.md

