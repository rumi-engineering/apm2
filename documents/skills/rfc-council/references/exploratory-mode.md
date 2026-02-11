title: RFC EXPLORE Mode (v0 -> v2)

decision_tree:
  entrypoint: EXPLORATION_FLOW
  nodes[2]:
    - id: EXPLORATION_FLOW
      purpose: "Active codebase investigation to transition RFC from v0 (Discovery) to v2 (Grounded)."
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <RFC_ID> placeholders before running commands."
        - id: LOAD_V0_CONTEXT
          action: |
            Read RFC v0 files, specifically `08_risks_and_open_questions.yaml`.
            Extract list of codebase-related questions and missing technical context.

        - id: EXPLORATORY_COUNCIL
          action: |
            Invoke COUNCIL_PROTOCOL with lifecycle-adaptive SA roles for v0->v2:
            - SA-1 (Rigorist): Validate design hypotheses against existing system traits and patterns.
            - SA-2 (Feasibility): Perform mock implementation runs to verify technical grounding.
            - SA-3 (Anti-Cousin): Identify exact extension points in the codebase to prevent parallel abstractions.

            Constraint: Each SA selects **2 Anchor + 3 Random reasoning modes** from modes-of-reasoning.

        - id: CODEBASE_INVESTIGATION
          action: |
            For each open question in 08_risks_and_open_questions.yaml:
            1. **Mode 61 (Hermeneutic)**: Extract meaning from existing code/comments. What was the *intent* of the original author?
            2. **Mode 40 (Mechanistic)**: Reconstruct the causal chain of the existing component. How does it work internally?
            3. Map finding to CCP.
            4. Update RFC sections (02, 04, 07) with evidence-backed answers that respect existing mechanisms.

        - id: EMIT_V2
          action: |
            1. Update `00_meta.yaml` to `version: v2`.
            2. Populate `02_design_decisions.yaml` with rationale derived from codebase evidence.
            3. Reduce `08_risks_and_open_questions.yaml` to "last-mile" implementation details.

        - id: COMMIT_V2
          action: |
            ```bash
            git add documents/rfcs/RFC-XXXX/
            git commit -m "docs(RFC-XXXX): Transition to RFC v2 (Grounded phase)"
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
