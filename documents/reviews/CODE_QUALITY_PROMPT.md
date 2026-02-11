title: Code Quality Review Prompt
protocol:
  id: CODE-QUALITY-REVIEW
  version: 2.0.0
  type: executable_specification
  purpose: "Evaluate PR code quality, publish findings through FAC, and set a SHA-bound decision."

inputs[1]:
  - OPTIONAL_CONTEXT

outputs[2]:
  - ReviewCommentProjection
  - DecisionProjection

metadata_contract:
  invariants[3]:
    - '"head_sha" MUST equal reviewed_sha.'
    - '"pr_number" MUST match the prepared PR number exactly.'
    - "Set reviewed_sha = headRefOid."

references[16]:
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "Holonic model, truth/projection split, and verification-first behavior."
  - path: "@AGENTS.md"
    purpose: "Global repository instructions."
  - path: "@documents/security/SECURITY_POLICY.cac.json"
    purpose: "Cross-cutting policy guardrails."
  - path: "@documents/skills/rust-standards/references/06_triage_fast_scan.md"
    purpose: "Fast triage procedure."
  - path: "@documents/skills/rust-standards/references/08_invariant_mapping.md"
    purpose: "Invariant and contract mapping."
  - path: "@documents/skills/rust-standards/references/10_abstraction_and_simplification.md"
    purpose: "Complexity reduction checks."
  - path: "@documents/skills/rust-standards/references/16_error_handling_and_panic_policy.md"
    purpose: "Error handling expectations."
  - path: "@documents/skills/rust-standards/references/18_api_design_and_semver.md"
    purpose: "Public API compatibility and ergonomics."
  - path: "@documents/skills/rust-standards/references/20_testing_evidence_and_ci.md"
    purpose: "Test sufficiency expectations."
  - path: "@documents/skills/rust-standards/references/22_performance_review.md"
    purpose: "Performance regressions and hotspots."
  - path: "@documents/skills/rust-standards/references/24_dependency_and_build_surface.md"
    purpose: "Dependency and build-surface scrutiny."
  - path: "@documents/skills/rust-standards/references/26_severity_and_verdict.md"
    purpose: "Severity calibration."
  - path: "@documents/skills/rust-standards/references/28_required_actions_templates.md"
    purpose: "Finding statement quality."

decision_tree:
  entrypoint: STEP_1_DISCOVERY
  nodes[8]:
    - id: STEP_1_DISCOVERY
      purpose: "Discover FAC commands before execution."
      steps[7]:
        - action: "Read all files listed in references before proceeding."
        - action: command
          run: "apm2 fac review --help"
        - action: command
          run: "apm2 fac review prepare --help"
        - action: command
          run: "apm2 fac review publish --help"
        - action: command
          run: "apm2 fac review findings --help"
        - action: command
          run: "apm2 fac review decision --help"
        - action: command
          run: "apm2 fac review decision set --help"
      next: STEP_2_PREPARE_INPUTS

    - id: STEP_2_PREPARE_INPUTS
      purpose: "Materialize the PR review inputs from FAC."
      steps[4]:
        - action: command
          run: "apm2 fac review prepare --json"
          capture_as: prepare_json
        - action: parse_json
          from: prepare_json
          extract: [repo, pr_number, pr_url, head_sha, diff_path, commit_history_path, temp_dir]
        - action: "Set headRefOid = head_sha. Set reviewed_sha = headRefOid."
        - action: stop_if
          if: "diff_path is empty OR head_sha is empty"
          message: "STOP-NO-PREPARED-INPUTS: fac review prepare did not return required fields."
      next: STEP_3_COLLECT_CONTEXT

    - id: STEP_3_COLLECT_CONTEXT
      purpose: "Collect quality standards and relevant module context."
      steps[5]:
        - action: read_file
          path: "$diff_path"
        - action: read_file
          path: "$commit_history_path"
        - action: command
          run: "rg --files -g 'AGENTS.md' crates/apm2-core crates/apm2-cli"
          capture_as: module_agents_md
        - action: selective_read
          from: module_agents_md
          rule: "Read AGENTS.md files adjacent to modules touched by the diff."
        - action: selective_read
          rule: "Read RFC/ticket/doc references linked from touched files when necessary for intent verification."
      next: STEP_4_ANALYZE

    - id: STEP_4_ANALYZE
      purpose: "Evaluate correctness, maintainability, and test evidence."
      lenses[6]:
        - lens: "Invariant Preservation"
          focus: "Behavioral regressions, hidden coupling, invalid assumptions."
        - lens: "API and Type Surface"
          focus: "Semantics, naming, compatibility, ergonomics."
        - lens: "Failure Handling"
          focus: "Error paths, fail-closed behavior, observability."
        - lens: "Testing Sufficiency"
          focus: "Missing tests, weak assertions, absent negative cases."
        - lens: "Performance / Resource Use"
          focus: "Hot-path regressions, needless allocations, expensive loops."
        - lens: "Documentation Coherence"
          focus: "Code/docs/AGENTS.md alignment."
      next: STEP_5_WRITE_FINDINGS

    - id: STEP_5_WRITE_FINDINGS
      purpose: "Write the reviewer-authored finding body (no manual metadata block)."
      steps[3]:
        - action: write_file
          path: "$temp_dir/code_quality_findings.md"
          required_structure:
            - "## Code Quality Review: PASS | FAIL"
            - "Reviewed SHA: $head_sha"
            - "### **BLOCKER FINDINGS**"
            - "### **MAJOR FINDINGS**"
            - "### **MINOR FINDINGS**"
            - "### **NITS**"
            - "### **WAIVED FINDINGS**"
        - action: quality_rule
          rule: "Each non-empty finding includes path, impact, and required action."
        - action: classify
          output: [blocker_count, major_count, minor_count, nit_count, verdict]
      next: STEP_6_PUBLISH

    - id: STEP_6_PUBLISH
      purpose: "Publish through FAC projection path only."
      steps[1]:
        - action: command
          run: "apm2 fac review publish --type code-quality --body-file \"$temp_dir/code_quality_findings.md\" --json"
          capture_as: publish_json
      next: STEP_7_SET_DECISION

    - id: STEP_7_SET_DECISION
      purpose: "Write SHA-bound decision for code-quality dimension."
      decisions[2]:
        - if: "blocker_count == 0 AND major_count == 0"
          then:
            action: command
            run: "apm2 fac review decision set --dimension code-quality --decision approve --reason \"PASS for $head_sha\" --json"
        - if: "blocker_count > 0 OR major_count > 0"
          then:
            action: command
            run: "apm2 fac review decision set --dimension code-quality --decision deny --reason \"BLOCKER/MAJOR findings for $head_sha\" --json"
      note: "Decision command removes prepared tmp review inputs by default. Use --keep-prepared-inputs only when debugging."
      next: STEP_8_VERIFY_AND_STOP

    - id: STEP_8_VERIFY_AND_STOP
      purpose: "Verify projection and end deterministically."
      steps[2]:
        - action: command
          run: "apm2 fac review findings --json"
        - action: output
          text: "DONE"
      stop: true
