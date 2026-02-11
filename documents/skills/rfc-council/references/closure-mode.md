title: RFC FINALIZE Mode (v2 -> v4)

decision_tree:
  entrypoint: CLOSURE_FLOW
  nodes[2]:
    - id: CLOSURE_FLOW
      purpose: "Final architectural convergence to transition RFC from v2 (Grounded) to v4 (Standard)."
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <RFC_ID> placeholders before running commands."
        - id: LOAD_V2_CONTEXT
          action: |
            Read RFC v2 files. Verify that most open questions have been answered.

        - id: CLOSURE_COUNCIL
          action: |
            Invoke COUNCIL_PROTOCOL with lifecycle-adaptive SA roles for v2->v4:
            - SA-1: Force convergence on architectural decisions.
            - SA-2: Finalize execution strategy and resource impacts.
            - SA-3: Perform final security assurance case (CAE Tree).

            Constraint: Each SA selects **2 Anchor + 3 Random reasoning modes** from modes-of-reasoning.

        - id: FORCED_CONVERGENCE
          action: |
            For any remaining questions in 08_risks_and_open_questions.yaml:
            1. Provide a definitive answer OR
            2. Explicitly defer to a future RFC (document deferral in 00_meta.yaml).
            3. Ensure all placeholders in RFC files are replaced with substantive content.

        - id: FINAL_ASSURANCE_CASE
          action: |
            Execute **Mode 36 (Assurance-Case)** to synthesize the v4 Confidence Certificate:
            1. TOP CLAIM: "RFC-XXXX satisfies all PRD requirements and preserves system invariants."
            2. STRATEGY: Decompose by gate category (SCHEMA, ATOMICITY, SECURITY, etc.).
            3. EVIDENCE: Link each sub-claim to a specific artifact (Mode 8 output, test results, CCP mapping).
            4. REBUTTAL: Log red-team challenges (Mode 79) and their resolutions.

            All claims must reach HIGH confidence before v4 approval.

        - id: EMIT_V4
          action: |
            1. Update `00_meta.yaml` to `version: v4`.
            2. Set status to `APPROVED`.
            3. Generate final governance gate content in `09_governance_and_gates.yaml`.

        - id: COMMIT_V4
          action: |
            ```bash
            git add documents/rfcs/RFC-XXXX/
            git commit -m "docs(RFC-XXXX): Finalize RFC v4 (Standard phase)"
            ```
      decisions[1]:
        - id: FINISHED
          if: "always"
          then:
            next: STOP

    - id: STOP
      purpose: "Terminate."
      steps[1]:
        - id: DONE
          action: "output DONE and nothing else, your task is complete."
