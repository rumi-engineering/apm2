title: RSI Modes-of-Reasoning Workflow

decision_tree:
  entrypoint: INIT_AND_SELECT
  nodes:
    - id: INIT_AND_SELECT
      purpose: "Map arguments to a target artifact or auto-select one."
      steps:
        - id: MAP_TARGET
          action: "Parse $ARGUMENTS. Map mode number/name to `artifacts/{NN}-*.json` or use provided path. If empty, select your 'favorite' universally-applicable candidate based on `selector.json` heuristics and provide a 3-bullet justification for the choice."
        - id: SET_TARGET_FILE
          action: "Assign chosen path to TARGET_FILE."
      decisions:
        - id: TARGET_SELECTED
          if: "TARGET_FILE is set"
          then:
            next_node: DIAGNOSE
    
    - id: DIAGNOSE
      purpose: "Score the target file and decide if improvement is needed."
      steps:
        - id: READ_TARGET
          action: "Read TARGET_FILE completely."
        - id: SCORE_TARGET
          action: "Score (1-5) on: Density, Clarity, Distinctions, Misuse-resistance, Artifact-orientation."
      decisions:
        - id: NEEDS_IMPROVEMENT
          if: "Any score < 4 OR non-trivial improvements identified"
          then:
            next_node: REFINE
        - id: ALREADY_OPTIMAL
          if: "All scores >= 4 AND only style nits remaining"
          then:
            next_node: INIT_AND_SELECT # Pick next best candidate if auto-selected

    - id: REFINE
      purpose: "Plan and implement high-density edits."
      steps:
        - id: PLAN_EDITS
          action: "Ensure headings: What it is, What it outputs, How it differs, Best for, Failure mode, Related modes. Plan density additions (Procedure, Checklist, Micro-example)."
        - id: ENFORCE_DENSITY
          action: "Convert vague advice into concrete criteria/steps/tests. Add mitigations for failure modes."
        - id: APPLY_EDIT
          action: "Modify TARGET_FILE. Ensure link consistency."
      next_node: VERIFY

    - id: VERIFY
      purpose: "Final gate for density and actionability."
      steps:
        - id: SELF_REVIEW
          action: "Verify outputs match procedure, boundaries are crisp, and mitigations are testable."
        - id: PRODUCE_OUTPUT
          action: "Provide diff and brief changelog."
