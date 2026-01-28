title: Code Quality Review Prompt
protocol:
  id: CODE-QUALITY-REVIEW
  version: 1.0.0
  type: executable_specification
  constraints[3]:
    - "No local execution: For efficiency and focus, reviewers DO NOT run build, test, or lint commands locally."
    - "Static analysis only: Focus on code quality, design, invariants, and adherence to holonic principles."
    - "CI Reliance: Assume minor formatting and auto-lintable errors are handled by CI. CI will block on test failures."
  inputs[2]:
    - PR_URL
    - HEAD_SHA
  outputs[2]:
    - PRComment
    - StatusCheck

variables:
  PR_URL: "$PR_URL"
  HEAD_SHA: "$HEAD_SHA"

decision_tree:
  entrypoint: PHASE_0_BOOTSTRAP
  nodes[7]:
    - id: PHASE_0_BOOTSTRAP
      purpose: "Load repo-wide guidance and security invariants before review actions."
      context_files[26]:
        - path: AGENTS.md
          purpose: "Repository-wide agent instructions."
        - path: documents/README.md
        - path: documents/skills/README.md
          purpose: "Development workflow, required commands, and CI expectations."
        - path: documents/security/AGENTS.md
          purpose: "Security documentation index and quick reference."
        - path: documents/security/SECURITY_POLICY.md
          purpose: "Security invariants and modes."
        - path: documents/skills/laws-of-holonic-agent-systems/references/holonic-agent-network/SKILL.md
          purpose: "Core holonic philosophy and constraints."
        - path: documents/skills/laws-of-holonic-agent-systems/references/unified-theory.md
          purpose: "Grand unified theory of agent-native holonic software (dcp://apm2.local/governance/holonic_unified_theory@v1)."
        - path: documents/skills/laws-of-holonic-agent-systems/references/holonic-agent-network/references/agent-native-software.md
          purpose: "Agent-native architecture doctrine."
        - path: documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md
          purpose: "APM2 safe patterns and anti-patterns (token-efficient index)."
        - path: documents/security/SECURITY_CHECKLIST.md
          purpose: "Security review checklist."
        - path: documents/skills/rust-textbook/09_unsafe_rust_obligations.md
          purpose: "Unsafe proof obligations + APM2 unsafe policy."
        - path: documents/skills/review-rust/SKILL.md
          purpose: "Core Rust review protocol."
        - path: documents/skills/review-rust/references/00_operating_mode.md
          purpose: "Reviewer audit posture."
        - path: documents/skills/review-rust/references/01_inputs_and_stop_conditions.md
          purpose: "Review input validation."
        - path: documents/skills/review-rust/references/02_qcp_classification.md
          purpose: "Quality Control Point scoring."
        - path: documents/skills/review-rust/references/03_triage_fast_scan.md
          purpose: "Fast risk detection."
        - path: documents/skills/review-rust/references/04_invariant_mapping.md
          purpose: "Mapping code to invariants."
        - path: documents/skills/review-rust/references/05_abstraction_and_simplification.md
          purpose: "Design and abstraction review."
        - path: documents/skills/review-rust/references/06_rust_soundness_and_unsafe.md
          purpose: "Memory safety and unsafe code audit."
        - path: documents/skills/review-rust/references/07_allocator_arena_pool_review.md
          purpose: "Memory management audit."
        - path: documents/skills/review-rust/references/08_error_handling_and_panic_policy.md
          purpose: "Failure semantics review."
        - path: documents/skills/review-rust/references/09_api_design_and_semver.md
          purpose: "API contract and semver review."
        - path: documents/skills/review-rust/references/10_testing_evidence_and_ci.md
          purpose: "Verification and CI review."
        - path: documents/skills/review-rust/references/11_performance_review.md
          purpose: "Resource and performance audit."
        - path: documents/skills/review-rust/references/12_dependency_and_build_surface.md
          purpose: "Supply chain and build audit."
        - path: documents/skills/review-rust/references/13_severity_and_verdict.md
          purpose: "Findings severity and final verdict."
        - path: documents/skills/review-rust/references/14_required_actions_templates.md
          purpose: "Review output templates."
      steps[1]:
        - id: READ_BASELINE_CONTEXT
          action: "Read every context file listed above and record invariants, required gates, and review constraints."
      next: PHASE_1_COLLECT_PR_IDENTITY

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
          extract[6]:
            - pr_number
            - pr_title
            - pr_body
            - files
            - additions
            - deletions
        - id: FETCH_DIFF
          action: command
          run: "gh pr diff $PR_URL"
          capture_as: diff_content
        - id: EXTRACT_TICKET_BINDING
          action: parse_text
          from_fields[2]:
            - pr_title
            - pr_body
          patterns[2]:
            - name: ticket_id
              regex: "TCK-[0-9]{5}"
            - name: rfc_id
              regex: "RFC-[0-9]{4}"
          store_as[2]:
            - ticket_id
            - rfc_id
      outputs[9]:
        - pr_number
        - pr_title
        - pr_body
        - files
        - additions
        - deletions
        - diff_content
        - ticket_id
        - rfc_id
      next: PHASE_2_GATHER_TICKET_CONTEXT

    - id: PHASE_2_GATHER_TICKET_CONTEXT
      purpose: "Understand what the PR is supposed to accomplish."
      steps[1]:
        - id: SET_TICKET_PATHS
          action: define_paths
          ticket_paths:
            decomposition: "documents/rfcs/${rfc_id}/06_ticket_decomposition.yaml"
            design_decisions: "documents/rfcs/${rfc_id}/02_design_decisions.yaml"
            meta: "documents/work/tickets/${ticket_id}.yaml"
            body: "documents/work/tickets/${ticket_id}.md"
      decisions[5]:
        - id: HANDLE_MISSING_TICKET
          if: "ticket_id is empty OR no ticket_id found in pr_title/pr_body"
          then:
            trivial_changes[3]:
              - "typo fixes"
              - "comment updates"
              - "dependency bumps with no API change"
            actions[1]:
              - "Classify the change set as trivial or non-trivial using the list above."
            branches[2]:
              - condition: "change_set_is_trivial == true"
                actions[1]:
                  - "Proceed without binding requirement."
              - condition: "change_set_is_trivial == false"
                actions[1]:
                  - "EMIT StopCondition STOP-NO-BINDING severity BLOCKER message 'Non-trivial changes require binding ticket'."
                stop: true
        - id: READ_RFC_DESIGN_DECISIONS
          if: "rfc_id found AND ticket_paths.design_decisions exists"
          then:
            actions[1]:
              - "Read RFC design decisions file to understand architectural constraints and normative justifications (AD-XXXX)."
        - id: READ_TICKET_DECOMPOSITION
          if: "ticket_id found AND rfc_id exists AND ticket_paths.decomposition exists"
          then:
            actions[1]:
              - "Read ticket decomposition file."
            extract[6]:
              - "scope.in_scope[]"
              - "scope.out_of_scope[] (context only; out-of-scope work is not a defect unless it introduces risk or violates constraints)"
              - "binds.requirement_ids[]"
              - "binds.evidence_ids[]"
              - "definition_of_done.criteria[]"
              - "dependencies[]"
            post_actions[1]:
              - "Verify dependencies[] tickets are merged/closed."
        - id: READ_TICKET_META
          if: "ticket_id found AND ticket_paths.meta exists"
          then:
            actions[1]:
              - "Read ticket meta file for context (owner, status, constraints, metadata)."
        - id: READ_TICKET_BODY
          if: "ticket_id found AND ticket_paths.body exists"
          then:
            actions[1]:
              - "Read ticket body for implementation notes, acceptance criteria, and edge cases."
      next: PHASE_4_ANALYZE_CHANGED_FILES

    - id: PHASE_4_ANALYZE_CHANGED_FILES
      purpose: "Understand what code was modified and in what context."
      assumptions[2]:
        - "Assume minor formatting issues and auto-lintable errors are handled by CI; focus on code quality, correctness, and design."
        - "Adhere to 'No local execution' constraint: Focus on static analysis; do not execute tests or build commands."
      steps[2]:
        - id: REVIEW_EACH_CHANGED_FILE
          action: for_each_file
          source: files
          cases[3]:
            - match: "file_path ends_with .rs"
              actions[1]:
                - "Read entire file to understand context."
            - match: "file_path matches any config pattern"
              patterns[4]:
                - "*.toml"
                - "*.yaml"
                - "*.json"
                - ".cargo/*"
              actions[1]:
                - "Read and verify syntax/correctness."
            - match: "file_path matches any documentation pattern"
              patterns[3]:
                - "*.md"
                - "documents/README.md"
                - "documents/skills/README.md"
              actions[1]:
                - "Read and verify accuracy against code."
        - id: READ_ADJACENT_CONTEXT
          action: for_each_modified_rust_file
          actions[3]:
            - "Read mod.rs in the same directory (if present)."
            - "Read related test files: *_test.rs and tests/*.rs."
            - "Read any AGENTS.md in the module directory."
      next: PHASE_5_EXECUTE_REVIEW

    - id: PHASE_5_EXECUTE_REVIEW
      purpose: "Apply review criteria and generate findings."
      context_files[3]:
        - path: documents/skills/review-rust/SKILL.md
          purpose: "Primary review protocol and modules."
        - path: documents/skills/review-rust/references/
          purpose: "Reference modules invoked by review-rust."
        - path: documents/skills/rust-textbook/SKILL.md
          purpose: "Rust principles referenced by review-rust."
      steps[5]:
        - id: LOAD_REVIEW_GUIDELINES
          action: "Read the review skill and the specific reference modules it invokes for this review."
        - id: ANALYZE_CHANGESET_CONTEXT
          action: "Analyze the diff and surrounding context to identify the changed components, risk areas, and relevant Rust domains (e.g., ownership, concurrency, unsafe, API design, error handling, performance, testing, security)."
        - id: SELECT_REVIEW_FRAMEWORKS
          action: "Choose the applicable review modules and Rust reference sections based on the changeset analysis. Record which modules are applied and why."
          sources:
            review_modules: "documents/skills/review-rust/references/"
            rust_reference: "documents/skills/rust-textbook/"
          output: modules_applied
        - id: APPLY_REVIEW_FRAMEWORKS
          action: "Apply the selected frameworks to the changed code and its context. Use the prompts below as optional lenses, not mandatory checklist items. Use your judgement to provide the most constructive review possible."
          considerations:
            scope_and_intent:
              - "Does the change set match the documented intent and constraints from ticket/RFC context?"
              - "Note any unrequested changes for context; only flag if they introduce risk or violate constraints."
            rust_soundness_and_correctness:
              - "Are ownership, lifetimes, and borrowing consistent with Rust guarantees?"
              - "If unsafe exists, is it justified, minimal, and documented?"
              - "Are invariants explicit and enforced?"
            failure_and_error_models:
              - "Are error types and propagation appropriate for the API surface?"
              - "Are failures observable and actionable?"
              - "Does the error context support causal reconstruction? Verify that error messages and tracing spans bind to stable identities (e.g., WorkID, SessionID) to allow for a deterministic 'why-chain' during failure audit."
            testing_and_evidence:
              - "Do tests exercise the new or changed behavior?"
              - "Are edge cases or failure paths covered where relevant?"
              - "Do tests provide negative evidence (falsification)? Verify that implementation invariants are strictly enforced by testing the inverse of happy paths and edge cases where silent failure might occur."
            documentation_and_communication:
              - "Are public APIs and behavior changes documented?"
              - "Are module-level constraints and AGENTS.md updates accurate?"
            performance_and_resources:
              - "Are new allocations, clones, or hot paths justified?"
              - "Any regressions or algorithmic risks introduced?"
            dependency_and_security:
              - "Do new dependencies or feature flags introduce risk or policy violations?"
              - "Any security-sensitive changes needing extra scrutiny?"
        - id: GENERATE_FINDINGS
          action: "Create findings using the schema below and record positive observations grounded in evidence."
          finding_schema[1]:
            - severity: "BLOCKER | MAJOR | MINOR | NIT"
              location: "file_path:line_number"
              issue: "Description of the problem"
              remediation: "What needs to change"
              proof_requirement: "CODE | TEST | DOC | CI"
      outputs[7]:
        - findings
        - positive_observations
        - scope_status
        - in_scope_checklist
        - dod_checklist
        - modules_applied
      next: PHASE_6_COMPUTE_VERDICT

    - id: PHASE_6_COMPUTE_VERDICT
      purpose: "Compute PASS/FAIL based on findings."
      steps[2]:
        - id: APPLY_VERDICT_RULES
          action: "Compute blocker_count and major_count from findings."
          verdict_rules:
            PASS:
              condition: "blocker_count == 0 AND major_count == 0"
            FAIL:
              condition: "blocker_count > 0 OR major_count > 0"
        - id: DEFINE_SEVERITY
          action: "Use severity definitions to classify findings."
          severity_definitions:
            BLOCKER[4]:
              - "Missing required functionality (in_scope not implemented)"
              - "Unsound unsafe code"
              - "Security vulnerability"
              - "Data loss risk"
            MAJOR[4]:
              - "Missing tests for new functionality"
              - "Acceptance criteria not met"
              - "API design issues"
              - "Performance regression"
            MINOR[3]:
              - "Non-idiomatic code"
              - "Missing documentation"
              - "Inconsistent naming"
            NIT[2]:
              - "Style preferences"
              - "Optional improvements"
      decisions[1]:
        - id: SET_VERDICT
          if: "blocker_count == 0 AND major_count == 0"
          then:
            actions[1]:
              - "Set verdict = PASS."
          else:
            actions[1]:
              - "Set verdict = FAIL."
      outputs[3]:
        - blocker_count
        - major_count
        - verdict
      next: PHASE_7_EXECUTE_REQUIRED_ACTIONS

    - id: PHASE_7_EXECUTE_REQUIRED_ACTIONS
      purpose: "Publish results to the PR and set status checks."
      requirements[1]:
        - "CRITICAL: Both actions MUST be executed."
      steps[2]:
        - id: FORMAT_FINDINGS_FOR_COMMENT
          action: "Format findings using the required markdown format."
          findings_format_lines[3]:
            - "- **[SEVERITY]** `file_path:line_number`"
            - "  - Issue: description"
            - "  - Remediation: what to fix"
        - id: POST_PR_COMMENT
          action: command
          run_lines[25]:
            - "gh pr comment $PR_URL --body \"$(cat <<'EOF'"
            - "## Code Quality Review"
            - ""
            - "**Ticket:** ${ticket_id}"
            - "**Scope Compliance:** ${scope_status}"
            - ""
            - "### Scope Verified"
            - "**In-scope items implemented:**"
            - "${in_scope_checklist}"
            - ""
            - "### Definition of Done"
            - "${dod_checklist}"
            - ""
            - "### Findings"
            - "${findings_formatted}"
            - ""
            - "### Positive Observations"
            - "${positive_observations}"
            - ""
            - "### Verdict: ${verdict}"
            - "EOF"
            - ")\""
      decisions[1]:
        - id: UPDATE_STATUS_CHECK
          if: "verdict == PASS"
          then:
            actions[1]:
              - "Run status check command for PASS."
            command: "gh api --method POST \"/repos/{owner}/{repo}/statuses/$HEAD_SHA\" -f state=\"success\" -f context=\"ai-review/code-quality\" -f description=\"Code quality review passed\""
          else:
            actions[1]:
              - "Run status check command for FAIL."
            command: "gh api --method POST \"/repos/{owner}/{repo}/statuses/$HEAD_SHA\" -f state=\"failure\" -f context=\"ai-review/code-quality\" -f description=\"Code quality review found issues - see PR comments\""

reference:
  paths:
    rfc_root: "documents/rfcs/${rfc_id}/"
    ticket_decomposition: "documents/rfcs/${rfc_id}/06_ticket_decomposition.yaml"
    ticket_meta: "documents/work/tickets/${ticket_id}.yaml"
    ticket_body: "documents/work/tickets/${ticket_id}.md"
    review_skill: "documents/skills/review-rust/SKILL.md"
    review_refs: "documents/skills/review-rust/references/"
    agents_md: "${module_path}/AGENTS.md"
  commands:
    pr_metadata: "gh pr view $PR_URL --json number,title,body,author,files,additions,deletions"
    pr_diff: "gh pr diff $PR_URL"
    post_comment: "gh pr comment $PR_URL --body '...'"
    set_status_pass: "gh api --method POST \"/repos/{owner}/{repo}/statuses/$HEAD_SHA\" -f state=\"success\" -f context=\"ai-review/code-quality\" -f description=\"Code quality review passed\""
    set_status_fail: "gh api --method POST \"/repos/{owner}/{repo}/statuses/$HEAD_SHA\" -f state=\"failure\" -f context=\"ai-review/code-quality\" -f description=\"Code quality review found issues - see PR comments\""
