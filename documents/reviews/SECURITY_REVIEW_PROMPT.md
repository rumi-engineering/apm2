title: Security Review Prompt
protocol:
  id: SECURITY-REVIEW
  version: 2.0.0
  type: executable_specification
  constraints[4]:
    - "Independent audit: Derive truth from diff and binding artifacts, not implementer narrative."
    - "Fail-closed: Unverifiable security claims = BLOCK."
    - "No local execution: Static analysis only; rely on evidence bundles if provided."
    - "No repository edits: Raise findings; do not propose patches."
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
  nodes[8]:
    - id: PHASE_0_BOOTSTRAP
      purpose: "Load security baseline and onboarding context."
      context_files[11]:
        - path: documents/security/SECURITY_POLICY.md
        - path: documents/security/CI_SECURITY_GATES.md
        - path: documents/security/THREAT_MODEL.md
        - path: documents/security/SECRETS_MANAGEMENT.md
        - path: documents/skills/rust-textbook/SKILL.md
        - path: documents/skills/glossary/SKILL.md
        - path: documents/skills/modes-of-reasoning/references/79-adversarial-red-team.md
        - path: documents/skills/modes-of-reasoning/references/08-counterexample-guided.md
        - path: documents/skills/modes-of-reasoning/references/49-robust-worst-case.md
        - path: documents/skills/modes-of-reasoning/references/55-game-theoretic-strategic.md
        - path: documents/skills/modes-of-reasoning/references/36-assurance-case.md
      steps[1]:
        - id: READ_BASELINE
          action: "Read baseline documents and record invariants. Adopt the 5 mandatory security reasoning modes."
      next: PHASE_1_COLLECT_PR_IDENTITY

[...]

    - id: PHASE_6_COMPUTE_VERDICT
      purpose: "Assign final verdict and severity using Assurance-Case reasoning."
      severity_rubric:
        CRITICAL: "authn/authz bypass, crypto weakness, RCE, secret exfiltration, fail-open in SCP."
        HIGH: "DoS in SCP, corruption-stop failure, widened egress without policy."
        MEDIUM: "Missing strict parsing (deny_unknown_fields), missing timeouts/limits."
        LOW: "Non-SCP hygiene, refactors without boundary change."
      rules:
        BLOCK: "any CRITICAL or HIGH findings."
        RE-AUDIT: "MANDATORY if SCP == YES and changes were made."
      steps[1]:
        - id: CONSTRUCT_ASSURANCE_CASE
          action: "Construct a Claim-Argument-Evidence structure for each finding and the final verdict."
      next: PHASE_7_EXECUTE_ACTIONS

    - id: PHASE_7_EXECUTE_ACTIONS
      purpose: "Post findings (Assurance-Case format) to PR and update status check."
      steps[2]:
        - id: POST_COMMENT
          action: command
          run: "gh pr comment $PR_URL --body \"$FINDINGS_ASSURANCE_CASE\""
        - id: UPDATE_STATUS
          action: command
          run: |
            IF verdict == PASS: "cargo xtask security-review-exec approve $PR_URL"
            ELSE: "cargo xtask security-review-exec deny $PR_URL --reason \"$FINDINGS_ASSURANCE_CASE\""

    - id: PHASE_1_COLLECT_PR_IDENTITY
      purpose: "Gather PR metadata, diff, and ticket/RFC bindings."
      steps[3]:
        - id: FETCH_PR_DATA
          action: command
          run: "gh pr view $PR_URL --json number,title,body,files && gh pr diff $PR_URL"
          capture_as: pr_bundle
        - id: EXTRACT_BINDINGS
          action: parse_text
          from: pr_bundle
          patterns:
            ticket_id: "TCK-[0-9]{5}"
            rfc_id: "RFC-[0-9]{4}"
            waiver_id: "WVR-[0-9]{4}"
        - id: STOP_IF_NO_BINDING
          if: "ticket_id is empty AND rfc_id is empty"
          then:
            action: "EMIT StopCondition STOP-NO-BINDING severity BLOCK message 'Security review requires binding ticket/RFC'."
            stop: true
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
          strategy: "Map compromise propagation paths across holon boundaries. Ask: 'Can a leaf-node compromise trick a parent into a confused-deputy action?'"
          reasoning: [55, 49] # Strategic & Robust
          laws: [5] # Dual-Axis Containment
        - lens: "Audit the 'Invisible Contract'"
          strategy: "Search for what ISN'T there. If a protocol message enters, where is the economic cost or resource cap?"
          reasoning: [49] # Robust
          laws: [6] # MDL as a Gated Budget
        - lens: "Treat Protocol as Code"
          strategy: "Game the protocol logic for downgrade attacks or canonicalization ambiguity (AD-VERIFY-001)."
          reasoning: [55] # Strategic
        - lens: "Search for 'Entropy Leaks'"
          strategy: "Find sequences of partial failures/restarts that leave the system in an 'impossible' state that bypasses a gate."
          reasoning: [8] # Counterexample-Guided
          laws: [11] # Idempotent Actuation
        - lens: "Demand 'Negative Evidence'"
          strategy: "Reject parsers/boundaries unless they include a 'corpus of pain' proving they fail correctly under stress."
          reasoning: [8] # Counterexample-Guided
        - lens: "The 'Assurance Case' Mindset"
          strategy: "Construct the final security case: 'What is the specific evidence that this PR does not degrade the branch posture?'"
          reasoning: [36] # Assurance-Case
        - lens: "Side-Channel & Timing Sensitivity"
          strategy: "Search for secret-dependent branching or indexing. Demand constant-time operations for ALL sensitive comparisons."
          reasoning: [8, 49] # Counterexample-Guided & Robust
          references: ["documents/skills/rust-textbook/19_security_adjacent_rust.md"]
      audit_categories[6]:
        - category: "Identity, Cryptography, and Wire Semantics"
          focus: "Signing, verification, hashing, and deterministic representation."
          references:
            - documents/security/THREAT_MODEL.md
            - documents/security/SECRETS_MANAGEMENT.md
            - documents/skills/rust-textbook/16_io_protocol_boundaries.md
            - documents/skills/rust-textbook/19_security_adjacent_rust.md
            - documents/skills/laws-of-holonic-agent-systems/references/law_09.md (Temporal Pinning & Freshness)
        - category: "Network and IPC Boundaries"
          focus: "Parsing untrusted data, framing, and DoS mitigation."
          references:
            - documents/skills/rust-textbook/16_io_protocol_boundaries.md
            - documents/skills/rust-textbook/10_concurrency_atomics_memory_order.md
            - documents/skills/review-rust/references/08_error_handling_and_panic_policy.md
            - documents/skills/laws-of-holonic-agent-systems/references/law_05.md (Dual-Axis Containment)
            - documents/skills/laws-of-holonic-agent-systems/references/law_06.md (MDL as a Gated Budget)
            - documents/skills/laws-of-holonic-agent-systems/references/law_12.md (Bounded Search and Termination)
        - category: "Filesystem and Process Boundaries"
          focus: "Path traversal, temp files, shell injection, and permissions."
          references:
            - documents/skills/rust-textbook/15_paths_filesystem_os.md
            - documents/skills/review-rust/references/12_dependency_and_build_surface.md
            - documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md
            - documents/skills/laws-of-holonic-agent-systems/references/law_11.md (Idempotent Actuation)
        - category: "Ledger and Evidence Integrity"
          focus: "Append-only persistence, crash recovery, and history verification."
          references:
            - documents/security/SECURITY_POLICY.md
            - documents/skills/rust-textbook/16_io_protocol_boundaries.md
            - documents/skills/rust-textbook/25_time_monotonicity_determinism.md
            - documents/skills/laws-of-holonic-agent-systems/references/law_03.md (Monotone Ledger)
            - documents/skills/laws-of-holonic-agent-systems/references/law_07.md (Verifiable Summaries)
        - category: "Memory Safety and Soundness"
          focus: "Unsafe code, async cancellation safety, and resource exhaustion."
          references:
            - documents/skills/review-rust/references/06_rust_soundness_and_unsafe.md
            - documents/skills/rust-textbook/09_unsafe_rust_obligations.md
            - documents/skills/rust-textbook/11_async_pin_cancellation.md
            - documents/skills/laws-of-holonic-agent-systems/references/holonic-agent-system-defects/SKILL.md
        - category: "Gate, Policy, and Supply Chain"
          focus: "Changes to security docs, CI gates, and new dependencies."
          references:
            - documents/security/CI_SECURITY_GATES.md
            - documents/skills/review-rust/references/12_dependency_and_build_surface.md
            - documents/reviews/SECURITY_REVIEW_PROMPT.md
            - documents/skills/laws-of-holonic-agent-systems/references/law_08.md (Goodhart Resistance)
            - documents/skills/laws-of-holonic-agent-systems/references/law_14.md (Risk-Weighted Evidence)
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
              rule: "BLOCK unless valid, unexpired WVR-#### exists and is referenced."
            - id: STRICTNESS_INCREASE
              rule: "BLOCK unless bound RFC exists describing implementation as deterministic checks."
            - id: CLARIFICATION
              rule: "Allowed if precision is maintained."
      next: PHASE_6_COMPUTE_VERDICT

    - id: PHASE_6_COMPUTE_VERDICT
      purpose: "Assign final verdict and severity."
      severity_rubric:
        CRITICAL: "authn/authz bypass, crypto weakness, RCE, secret exfiltration, fail-open in SCP."
        HIGH: "DoS in SCP, corruption-stop failure, widened egress without policy."
        MEDIUM: "Missing strict parsing (deny_unknown_fields), missing timeouts/limits."
        LOW: "Non-SCP hygiene, refactors without boundary change."
      rules:
        BLOCK: "any CRITICAL or HIGH findings."
        RE-AUDIT: "MANDATORY if SCP == YES and changes were made."
      next: PHASE_7_EXECUTE_ACTIONS

    - id: PHASE_7_EXECUTE_ACTIONS
      purpose: "Post findings to PR and update status check."
      steps[2]:
        - id: POST_COMMENT
          action: command
          run: "gh pr comment $PR_URL --body \"$FINDINGS_TABLE\""
        - id: UPDATE_STATUS
          action: command
          run: |
            IF verdict == PASS: "cargo xtask security-review-exec approve $PR_URL"
            ELSE: "cargo xtask security-review-exec deny $PR_URL --reason \"$FINDINGS_TABLE\""

reference:
  paths:
    onboard: "cargo xtask security-review-exec onboard"
    waiver_schema: "documents/standards/schemas/05_waiver.schema.yaml"
    waiver_dir: "documents/work/waivers/"
