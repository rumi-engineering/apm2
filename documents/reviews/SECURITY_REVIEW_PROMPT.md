title: Security Review Prompt
protocol:
  id: SECURITY-REVIEW
  version: 3.0.0
  type: executable_specification
  purpose: "Evaluate PR security properties from FAC-prepared local inputs, publish findings through FAC, and set a SHA-bound decision."

inputs[1]:
  - OPTIONAL_CONTEXT

outputs[2]:
  - ReviewCommentProjection
  - DecisionProjection

constraints:
  forbidden_operations:
    - "NEVER run git commands that modify worktree state (git reset, git checkout, git clean, git stash, git rebase, git merge, git cherry-pick, git commit, git push, git pull, git fetch)."
    - "NEVER run gh commands that modify PR state (gh pr merge, gh pr close, gh pr edit)."
    - "NEVER use direct gh or git commands for any purpose. All repository and GitHub interactions MUST go through apm2 fac review commands exclusively."
    - "If the worktree is dirty or in a conflicted state, STOP and report the issue — do not attempt to fix it."
    - "All interactions with the repository MUST be read-only."

metadata_contract:
  invariants[3]:
    - '"head_sha" MUST equal reviewed_sha.'
    - '"pr_number" MUST match the prepared PR number exactly.'
    - "Set reviewed_sha = headRefOid."

references[27]:
  # Core security and policy
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "Truth/projection model, containment, and verification laws."
  - path: "@AGENTS.md"
    purpose: "Global repository instructions."
  - path: "@documents/security/SECURITY_POLICY.cac.json"
    purpose: "Authoritative security policy."
  - path: "@documents/security/THREAT_MODEL.cac.json"
    purpose: "Threat model baseline."
  - path: "@documents/security/SECRETS_MANAGEMENT.cac.json"
    purpose: "Secrets controls."
  - path: "@documents/security/NETWORK_DEFENSE.cac.json"
    purpose: "Network and interface threat matrix."
  - path: "@documents/skills/rust-standards/SKILL.md"
    purpose: "Rust correctness and safety standards."

  # Original rust-standards references (6)
  - path: "@documents/skills/rust-standards/references/12_rust_soundness_and_unsafe.md"
    purpose: "Unsafe/soundness obligations."
  - path: "@documents/skills/rust-standards/references/19_unsafe_rust_obligations.md"
    purpose: "Unsafe audit checklist."
  - path: "@documents/skills/rust-standards/references/21_concurrency_atomics_memory_order.md"
    purpose: "Concurrency and memory-ordering risks."
  - path: "@documents/skills/rust-standards/references/23_async_pin_cancellation.md"
    purpose: "Async cancellation and resource safety."
  - path: "@documents/skills/rust-standards/references/30_paths_filesystem_os.md"
    purpose: "Filesystem/process boundary controls."
  - path: "@documents/skills/rust-standards/references/31_io_protocol_boundaries.md"
    purpose: "Untrusted input and protocol handling."
  - path: "@documents/skills/rust-standards/references/34_security_adjacent_rust.md"
    purpose: "Security-adjacent anti-patterns."
  - path: "@documents/skills/rust-standards/references/39_hazard_catalog_checklists.md"
    purpose: "Security hazard catalog."
  - path: "@documents/skills/rust-standards/references/42_distributed_security_invariants.md"
    purpose: "Distributed invariant checks."
  - path: "@documents/skills/rust-standards/references/42_pcac_ajc_integration.md"
    purpose: "PCAC/AJC lifecycle integration checks for authority-bearing handlers."

  # NEW CRITICAL ADDITIONS: Foundational and Boundary Security (17)
  - path: "@documents/skills/rust-standards/references/01_contract_and_truth.md"
    purpose: "Primitive soundness invariants: type validity, initialization, pointer provenance, aliasing."
  - path: "@documents/skills/rust-standards/references/03_compilation_pipeline.md"
    purpose: "Macro expansion security, hidden unsafe, cfg-dependent code drift, dark code testing."
  - path: "@documents/skills/rust-standards/references/05_toolchain_cargo_build.md"
    purpose: "Build-time code execution, supply chain injection, feature safety, reproducibility."
  - path: "@documents/skills/rust-standards/references/09_ownership_borrowing_model.md"
    purpose: "Ownership authority, interior mutability protocols, reference invalidation, synchronization."
  - path: "@documents/skills/rust-standards/references/11_lifetimes_variance_hrtb.md"
    purpose: "Type variance, PhantomData correctness, auto-trait safety, dropck integrity."
  - path: "@documents/skills/rust-standards/references/13_traits_generics_coherence.md"
    purpose: "Trait coherence, blanket impl safety, auto-trait observability, downstream breakage."
  - path: "@documents/skills/rust-standards/references/14_allocator_arena_pool_review.md"
    purpose: "Allocator invariants: use-after-free, double-free, alignment, drop discipline, overflow."
  - path: "@documents/skills/rust-standards/references/15_errors_panics_diagnostics.md"
    purpose: "Panic-as-DoS, panic safety for unsafe, unwind boundaries, cascading failures."
  - path: "@documents/skills/rust-standards/references/17_layout_repr_drop.md"
    purpose: "Layout contracts, repr safety, drop ordering, partial initialization, resource guards."
  - path: "@documents/skills/rust-standards/references/25_api_design_stdlib_quality.md"
    purpose: "API safety and misuse resistance, invariant clarity, hidden DoS vectors, allocation contracts."
  - path: "@documents/skills/rust-standards/references/27_collections_allocation_models.md"
    purpose: "Memory DoS prevention, use-after-realloc, size math overflow, bounded stores, iteration."
  - path: "@documents/skills/rust-standards/references/29_unicode_text_graphemes.md"
    purpose: "Text security: UTF-8 validity, confusable normalization, identifier confusion attacks."
  - path: "@documents/skills/rust-standards/references/32_testing_fuzz_miri_evidence.md"
    purpose: "Verification methodology and tool gates: Miri, Loom, Proptest, Kani for risk anchors."
  - path: "@documents/skills/rust-standards/references/35_cfg_features_build_matrix.md"
    purpose: "Dark code coverage, build matrix enforcement, feature-gated security gaps, fail-closed flags."
  - path: "@documents/skills/rust-standards/references/38_ffi_and_abi.md"
    purpose: "FFI safety, ABI unwinding boundaries, ownership transfer, pointer validity, safe wrappers."
  - path: "@documents/skills/rust-standards/references/40_time_monotonicity_determinism.md"
    purpose: "Monotonic clocks, ordering invariants, consensus safety, distributed timeout protocols."
  - path: "@documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md"
    purpose: "APM2 security contracts: typed IDs, secret redaction, state machines, atomic writes, identity boundaries, fail-closed defaults."
  - path: "@documents/skills/rust-standards/references/42_pcac_ajc_integration.md"
    purpose: "PCAC/AJC authority lifecycle for privileged handlers: 4-step lifecycle, 7 semantic laws, security reviewer checklist for replay/revocation prevention."

decision_tree:
  entrypoint: STEP_1_DISCOVERY
  nodes[8]:
    - id: STEP_1_DISCOVERY
      purpose: "Discover FAC command surface and internalize all reference material before execution."
      steps[8]:
        - action: read_all_references
          rule: "Read every file listed in the references[] section IN FULL. Do not summarize, skip, or skim — details matter. Each reference contains threat vectors, invariants, checklists, and anti-patterns that are load-bearing for security review accuracy. Incomplete internalization produces false negatives."
        - action: read_module_agents
          rule: "For each crate/module touched by the PR diff, read its AGENTS.md (if it exists) in full. These contain module-specific invariants [INV-*] and contracts [CTR-*] whose violation constitutes a security finding."
        - action: command
          run: "apm2 fac review --help"
        - action: command
          run: "apm2 fac review prepare --help"
        - action: command
          run: "apm2 fac review publish --help"
        - action: command
          run: "apm2 fac review findings --help"
        - action: command
          run: "apm2 fac review verdict --help"
        - action: command
          run: "apm2 fac review verdict set --help"
      next: STEP_2_PREPARE_INPUTS

    - id: STEP_2_PREPARE_INPUTS
      purpose: "Prepare deterministic local review inputs for the current PR."
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
      purpose: "Collect security context for touched surfaces."
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
          rule: "Read additional RFC/ticket/security docs only when the diff references them or changes trust boundaries."
      next: STEP_4_ANALYZE

    - id: STEP_4_ANALYZE
      purpose: "Run threat-focused analysis on changed boundaries."
      threat_axes[8]:
        - axis: "Authentication/Authorization"
          focus: "Privilege checks, identity binding, allowlist integrity."
        - axis: "Input/Protocol Validation"
          focus: "Parser strictness, canonicalization, downgrade paths."
        - axis: "Filesystem/Process Boundary"
          focus: "Path traversal, command injection, unsafe temp-file handling."
        - axis: "Network/IPC Boundary"
          focus: "Untrusted payload handling, framing, denial-of-service vectors."
        - axis: "Cryptographic / Integrity Surface"
          focus: "Hash/signature usage, replay/drift exposure, deterministic verification."
        - axis: "Concurrency / Resource Exhaustion"
          focus: "Deadlock, race, starvation, unbounded memory/cpu growth."
        - axis: "Policy and Gate Strictness"
          focus: "Any strictness decrease in policy, gate, or provenance logic."
        - axis: "Authority Lifecycle Continuity (PCAC/AJC)"
          focus: "Authority-bearing handlers MUST enforce join -> revalidate -> consume -> effect with fail-closed deny paths and durable lifecycle evidence."
      next: STEP_5_WRITE_FINDINGS

    - id: STEP_5_WRITE_FINDINGS
      purpose: "Write security findings body (no manual metadata block)."
      steps[4]:
        - action: write_file
          path: "$temp_dir/security_findings.md"
          required_structure:
            - "## Security Review: PASS | FAIL"
            - "Reviewed SHA: $head_sha"
            - "### **BLOCKER FINDINGS**"
            - "### **MAJOR FINDINGS**"
            - "### **MINOR FINDINGS**"
            - "### **NITS**"
            - "### **WAIVED FINDINGS**"
        - action: quality_rule
          rule: "Each non-empty finding includes threat, exploit path, blast radius, and required remediation."
        - action: structural_rule
          rule: "If a handler has authority-bearing side effects but lacks AJC lifecycle enforcement (join -> revalidate -> consume -> effect), emit a MAJOR finding."
        - action: classify
          output: [blocker_count, major_count, minor_count, nit_count, verdict]
      next: STEP_6_PUBLISH

    - id: STEP_6_PUBLISH
      purpose: "Publish through FAC projection path only."
      steps[1]:
        - action: command
          run: "apm2 fac review publish --type security --body-file \"$temp_dir/security_findings.md\" --json"
          capture_as: publish_json
      next: STEP_7_SET_VERDICT

    - id: STEP_7_SET_VERDICT
      purpose: "Write SHA-bound verdict for security dimension."
      decisions[2]:
        - if: "blocker_count == 0 AND major_count == 0"
          then:
            action: command
            run: "apm2 fac review verdict set --dimension security --verdict approve --reason \"PASS for $head_sha\" --json"
        - if: "blocker_count > 0 OR major_count > 0"
          then:
            action: command
            run: "apm2 fac review verdict set --dimension security --verdict deny --reason \"BLOCKER/MAJOR findings for $head_sha\" --json"
      note: "Verdict command removes prepared tmp review inputs by default. Use --keep-prepared-inputs only when debugging."
      next: STEP_8_VERIFY_AND_STOP

    - id: STEP_8_VERIFY_AND_STOP
      purpose: "Verify projection and end deterministically."
      steps[2]:
        - action: command
          run: "apm2 fac review findings --json"
        - action: output
          text: "DONE"
      stop: true
