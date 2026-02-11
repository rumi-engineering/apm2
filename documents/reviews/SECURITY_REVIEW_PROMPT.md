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

metadata_contract:
  invariants[3]:
    - '"head_sha" MUST equal reviewed_sha.'
    - '"pr_number" MUST match the prepared PR number exactly.'
    - "Set reviewed_sha = headRefOid."

references[18]:
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

decision_tree:
  entrypoint: STEP_1_DISCOVERY
  nodes[8]:
    - id: STEP_1_DISCOVERY
      purpose: "Discover FAC command surface before execution."
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
      threat_axes[7]:
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
      next: STEP_5_WRITE_FINDINGS

    - id: STEP_5_WRITE_FINDINGS
      purpose: "Write security findings body (no manual metadata block)."
      steps[3]:
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
        - action: classify
          output: [blocker_count, major_count, minor_count, nit_count, verdict]
      next: STEP_6_PUBLISH

    - id: STEP_6_PUBLISH
      purpose: "Publish through FAC projection path only."
      steps[1]:
        - action: command
          run: "apm2 fac review publish --type security --body-file \"$temp_dir/security_findings.md\" --json"
          capture_as: publish_json
      next: STEP_7_SET_DECISION

    - id: STEP_7_SET_DECISION
      purpose: "Write SHA-bound decision for security dimension."
      decisions[2]:
        - if: "blocker_count == 0 AND major_count == 0"
          then:
            action: command
            run: "apm2 fac review decision set --dimension security --decision approve --reason \"PASS for $head_sha\" --json"
        - if: "blocker_count > 0 OR major_count > 0"
          then:
            action: command
            run: "apm2 fac review decision set --dimension security --decision deny --reason \"BLOCKER/MAJOR findings for $head_sha\" --json"
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
