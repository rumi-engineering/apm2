title: RFC Council Workflow

decision_tree:
  entrypoint: VALIDATE_AND_CLASSIFY
  nodes[1]:
    - id: VALIDATE_AND_CLASSIFY
      purpose: "Validate inputs and branch to the correct mode."
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <MODE_OPTIONAL> and <TARGET_ID> placeholders before running commands."
        - id: VALIDATE_ID
          action: |
            Validate input ID format:
            - CREATE mode: PRD_ID must match /^PRD-[0-9]{4}$/
            - REVIEW/REFINE mode: RFC_ID must match /^RFC-[0-9]{4}$/
            If invalid, reject with error.
        - id: LOCATE_INPUTS
          action: |
            Set paths based on mode:
            - CREATE: PRD root = documents/prds/{PRD_ID}/
            - REVIEW/REFINE: RFC root = documents/rfcs/{RFC_ID}/
                             Tickets = documents/work/tickets/TCK-*.yaml (filtered by rfc_id)
        - id: SELECT_MODE
          action: |
            If mode not provided:
            - If input is PRD-XXXX: default to CREATE
            - If input is RFC-XXXX: ask user to choose REVIEW or REFINE
        - id: SELECT_DEPTH
          action: |
            Compute depth based on impact:
            - ticket_count: <=5 (Low), 6-15 (Medium), >15 (High)
            - cross_crate_changes: 0 (Low), 1-2 (Medium), >2 (High)
            - net_new_files: <=3 (Low), 4-10 (Medium), >10 (High)

            Depth Algorithm:
            - STANDARD: all dimensions = low/medium
            - COUNCIL: any dimension = high OR --council flag
        - id: GATE_INVARIANT
          action: |
            Note fixed gate order:
            1. GATE-TCK-SCHEMA
            2. GATE-TCK-DEPENDENCY-ACYCLICITY
            3. GATE-TCK-SCOPE-COVERAGE
            4. GATE-TCK-CCP-MAPPING
            5. GATE-TCK-ATOMICITY
            6. GATE-TCK-IMPLEMENTABILITY
            7. GATE-TCK-ANTI-COUSIN
      decisions[3]:
        - id: MODE_CREATE
          if: "mode is CREATE"
          then:
            next_reference: references/create-mode.md
        - id: MODE_REVIEW
          if: "mode is REVIEW"
          then:
            next_reference: references/review-mode.md
        - id: MODE_REFINE
          if: "mode is REFINE"
          then:
            next_reference: references/refine-mode.md
