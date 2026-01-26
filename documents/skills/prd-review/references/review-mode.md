# REVIEW Mode

decision_tree:
  entrypoint: RUN_GATES
  nodes[1]:
    - id: RUN_GATES
      purpose: "Execute formal review gates and emit findings."
      steps[6]:
        - id: EXECUTE_DETERMINISTIC_GATES
          action: invoke_reference
          reference: references/REVIEW_RUBRIC.md
          purpose: "Run SCHEMA, LINT, TRACEABILITY, CCP-MAPPING, QUALITY, and EVIDENCE gates."
        - id: COMPUTE_DEPTH
          action: "Compute impact vector based on requirements, dependencies, abstractions, data classification, and blast radius."
          logic: |
            Impact Vector Computation:
            - requirement_count: ≤3 (Low), 4-10 (Medium), >10 (High)
            - external_dependencies: 0 (Low), 1-2 (Medium), >2 (High)
            - net_new_abstractions: 0 (Low), 1 (Medium), >1 (High)
            - data_classification: public (Low), internal (Medium), pii/confidential (High)
            - blast_radius: single_component (Low), cross_component (Medium), system_wide (High)

            Depth Algorithm:
            - LIGHT: all dimensions = low
            - STANDARD: any dimension = medium, none = high
            - DEEP: any dimension = high
            - COUNCIL: blast_radius = system_wide AND (net_new_abstractions > 2 OR north_star_alignment_requested)
        - id: CONTENT_REVIEW
          action: invoke_reference
          reference: references/ANGLE_PROMPTS.md
          purpose: "Execute required and optional review angles based on computed depth."
        - id: ADVERSARIAL_PASS
          action: invoke_reference
          reference: references/ADVERSARIAL_REVIEW_PROMPT.md
          condition: "depth is DEEP or 20% random sample of STANDARD"
        - id: COUNCIL_PROTOCOL
          action: invoke_reference
          reference: references/COUNCIL_PROTOCOL.md
          condition: "depth is COUNCIL"
        - id: EMIT_BUNDLE
          action: "Produce prd_review_{timestamp}.json evidence bundle."
      decisions[2]:
        - id: GATE_FAILED
          if: "any gate status is FAILED"
          then:
            stop: true
        - id: ALL_GATES_COMPLETED
          if: "all gates executed"
          then:
            stop: true
