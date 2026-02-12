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

references[30]:
  # Core guidance and policy
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "Holonic model, truth/projection split, and verification-first behavior."
  - path: "@AGENTS.md"
    purpose: "Global repository instructions."
  - path: "@documents/security/SECURITY_POLICY.cac.json"
    purpose: "Cross-cutting policy guardrails."

  # Original core standards (8)
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
  - path: "@documents/skills/rust-standards/references/42_pcac_ajc_integration.md"
    purpose: "Canonical PCAC/AJC integration pattern for authority-bearing handlers."

  # TIER 1 MANDATORY: Soundness and Invariant Enforcement (19)
  - path: "@documents/skills/rust-standards/references/01_contract_and_truth.md"
    purpose: "Primitive soundness invariants (type validity, initialization, alignment, data races)."
  - path: "@documents/skills/rust-standards/references/07_core_language_semantics.md"
    purpose: "Place model, move semantics, drop scopes, temporary lifetimes, pattern binding modes."
  - path: "@documents/skills/rust-standards/references/09_ownership_borrowing_model.md"
    purpose: "Ownership authority, interior mutability protocols, borrow-across-await hazards."
  - path: "@documents/skills/rust-standards/references/11_lifetimes_variance_hrtb.md"
    purpose: "Variance and auto-trait observability; PhantomData and Pin contracts."
  - path: "@documents/skills/rust-standards/references/13_traits_generics_coherence.md"
    purpose: "Coherence rules; trait bound SemVer impacts; auto-trait drift detection."
  - path: "@documents/skills/rust-standards/references/14_allocator_arena_pool_review.md"
    purpose: "Five allocator invariants: UAF, double-free, alignment, overlap, drop discipline."
  - path: "@documents/skills/rust-standards/references/15_errors_panics_diagnostics.md"
    purpose: "Panic safety, unwind discipline, structured logging, lint policy enforcement."
  - path: "@documents/skills/rust-standards/references/17_layout_repr_drop.md"
    purpose: "Repr contracts, layout stability, drop discipline, partial initialization."
  - path: "@documents/skills/rust-standards/references/25_api_design_stdlib_quality.md"
    purpose: "Misuse-resistant APIs: visibility, construction validation, borrowed vs owned."
  - path: "@documents/skills/rust-standards/references/27_collections_allocation_models.md"
    purpose: "Use-after-realloc prevention, size math overflow, bounded stores, deterministic iteration."
  - path: "@documents/skills/rust-standards/references/29_unicode_text_graphemes.md"
    purpose: "UTF-8 validity, text units, grapheme policies, confusable prevention."
  - path: "@documents/skills/rust-standards/references/32_testing_fuzz_miri_evidence.md"
    purpose: "Tool selection per risk anchor: Miri, Loom, Proptest, Kani gating."
  - path: "@documents/skills/rust-standards/references/33_performance_measurement.md"
    purpose: "Performance contracts, benchmark methodology, code-size/monomorphization control."
  - path: "@documents/skills/rust-standards/references/35_cfg_features_build_matrix.md"
    purpose: "Dark-code control, build matrix coverage, feature stability, fail-closed flags."
  - path: "@documents/skills/rust-standards/references/36_msrv_editions_maintenance.md"
    purpose: "MSRV enforcement, edition migrations, deprecation strategies."
  - path: "@documents/skills/rust-standards/references/37_macros_buildscripts_proc_macros.md"
    purpose: "Macro hygiene, hidden unsafe prevention, build-time execution control."
  - path: "@documents/skills/rust-standards/references/38_ffi_and_abi.md"
    purpose: "FFI validity, ABI unwinding, ownership transfer, safe wrapper patterns."
  - path: "@documents/skills/rust-standards/references/40_time_monotonicity_determinism.md"
    purpose: "Monotonic clocks, wall-clock hazards, distributed ordering, defensive duration handling."
  - path: "@documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md"
    purpose: "APM2-specific: typed IDs, secret redaction, state machines, atomic writes, identity boundaries."
  - path: "@documents/skills/rust-standards/references/42_pcac_ajc_integration.md"
    purpose: "PCAC/AJC integration guide for privileged handlers: canonical lifecycle, 7 semantic laws, reviewer checklist."

  # TIER 2 OPTIONAL: Educational and Context (2)
  - path: "@documents/skills/rust-standards/references/03_compilation_pipeline.md"
    purpose: "Phase-aware reasoning; macro expansion, dark code, drop/borrow checking semantics."
  - path: "@documents/skills/rust-standards/references/04_qcp_classification.md"
    purpose: "QCP risk escalation and proof-burden multiplier logic."

decision_tree:
  entrypoint: STEP_1_DISCOVERY
  nodes[8]:
    - id: STEP_1_DISCOVERY
      purpose: "Discover FAC commands and internalize all reference material before execution."
      steps[8]:
        - action: read_all_references
          rule: "Read every file listed in the references[] section IN FULL. Do not summarize, skip, or skim — details matter. Each reference contains invariants, contracts, checklists, and anti-patterns that are load-bearing for review accuracy. Incomplete internalization produces false negatives."
        - action: read_module_agents
          rule: "For each crate/module touched by the PR diff, read its AGENTS.md (if it exists) in full. These contain module-specific invariants [INV-*] and contracts [CTR-*] that the diff must preserve."
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
      lenses[7]:
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
        - lens: "PCAC Pattern Compliance"
          focus: "Authority-bearing handlers follow canonical PCAC lifecycle (join -> revalidate -> consume -> effect) and prefer PrivilegedPcacInputBuilder over manual join-input construction."
      next: STEP_5_WRITE_FINDINGS

    - id: STEP_5_WRITE_FINDINGS
      purpose: "Write the reviewer-authored finding body (no manual metadata block)."
      steps[4]:
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
        - action: structural_rule
          rule: "For PCAC-integrated handlers, verify canonical lifecycle ordering and builder usage; flag manual join-input construction or lifecycle drift as findings."
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
