# PRD Review Workflow

decision_tree:
  entrypoint: VALIDATE_AND_CLASSIFY
  nodes[1]:
    - id: VALIDATE_AND_CLASSIFY
      purpose: "Validate inputs and branch to the correct mode."
      steps[4]:
        - id: VALIDATE_ID
          action: "Ensure PRD_ID matches /^PRD-[0-9]{4}$/. If invalid, reject with error."
        - id: LOCATE_INPUTS
          action: "Set default PRD root to documents/prds/{PRD_ID}/. Allow interactive override."
        - id: SELECT_MODE
          action: "If mode is not provided, ask user to choose between CREATE, REFINE, or REVIEW."
        - id: GATE_INVARIANT
          action: "Note fixed gate order: 1. SCHEMA, 2. LINT, 3. TRACEABILITY, 4. CCP-MAPPING, 5. QUALITY, 6. EVIDENCE, 7. CONTENT."
      decisions[3]:
        - id: MODE_CREATE
          if: "mode is CREATE"
          then:
            next_reference: references/create-mode.md
        - id: MODE_REFINE
          if: "mode is REFINE"
          then:
            next_reference: references/refine-mode.md
        - id: MODE_REVIEW
          if: "mode is REVIEW"
          then:
            next_reference: references/review-mode.md
