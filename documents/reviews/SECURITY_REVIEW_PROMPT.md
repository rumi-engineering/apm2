title: Security Review Prompt
protocol:
  id: SECURITY-REVIEW
  version: 2.0.0
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

references[20]:
  - path: "@documents/skills/modes-of-reasoning/artifacts/79-adversarial-red-team.json"
    purpose: "Mode #79: Adversarial / Red-Team Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/08-counterexample-guided.json"
    purpose: "Mode #08: Counterexample-Guided Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/49-robust-worst-case.json"
    purpose: "Mode #49: Robust / Worst-Case Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/55-game-theoretic-strategic.json"
    purpose: "Mode #55: Game-Theoretic Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/36-assurance-case.json"
    purpose: "Mode #36: Assurance-Case Reasoning"
  - path: "@documents/security/SECURITY_POLICY.md"
    purpose: "Security Policy"
  - path: "@documents/security/CI_SECURITY_GATES.md"
    purpose: "CI Security Gates"
  - path: "@documents/security/THREAT_MODEL.md"
    purpose: "Threat Model"
  - path: "@documents/security/SECRETS_MANAGEMENT.md"
    purpose: "Secrets Management"
  - path: "@documents/skills/rust-standards/SKILL.md"
    purpose: "Rust Standards"
  - path: "@documents/skills/glossary/SKILL.md"
    purpose: "Project Glossary"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_03.md"
    purpose: "LAW-03: Monotone Ledger"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_05.md"
    purpose: "LAW-05: Dual-Axis Containment"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_06.md"
    purpose: "LAW-06: MDL as a Gated Budget"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_07.md"
    purpose: "LAW-07: Verifiable Summaries"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_08.md"
    purpose: "LAW-08: Goodhart Resistance"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_09.md"
    purpose: "LAW-09: Temporal Pinning & Freshness"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_11.md"
    purpose: "LAW-11: Idempotent Actuation"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_12.md"
    purpose: "LAW-12: Bounded Search and Termination"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_14.md"
    purpose: "LAW-14: Risk-Weighted Evidence"

decision_tree:
  entrypoint: PHASE_1_COLLECT_PR_IDENTITY
  nodes[7]:
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
              rule: "BLOCK unless valid, unexpired WVR-#### exists and is referenced."
            - id: STRICTNESS_INCREASE
              rule: "BLOCK unless bound RFC exists describing implementation as deterministic checks."
            - id: CLARIFICATION
              rule: "Allowed if precision is maintained."
      next: PHASE_6_COMPUTE_VERDICT

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
      steps[3]:
        - id: WRITE_FINDINGS
          action: write_file
          path: "security_findings.md"
          content: "$FINDINGS_ASSURANCE_CASE"
        - id: POST_COMMENT
          action: command
          run: "gh pr comment $PR_URL --body-file security_findings.md"
        - id: UPDATE_STATUS
          action: command
          run: |
            IF verdict == PASS: "cargo xtask security-review-exec approve $PR_URL && rm security_findings.md"
            ELSE: "cat security_findings.md | cargo xtask security-review-exec deny $PR_URL --reason - && rm security_findings.md"
