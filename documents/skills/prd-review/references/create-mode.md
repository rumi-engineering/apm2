# CREATE Mode

decision_tree:
  entrypoint: CREATE_FLOW
  nodes[2]:
    - id: CREATE_FLOW
      purpose: "Draft a new PRD from template."
      steps[5]:
        - id: GATHER_CONTEXT
          action: "Ask for PRD-ID, title, customer segment, problem statement, and scope."
        - id: COPY_TEMPLATE
          action: command
          run: "cp -r documents/prds/template documents/prds/{PRD_ID}"
        - id: DRAFT_CONTENT
          action: invoke_reference
          reference: references/CREATE_PRD_PROMPT.md
        - id: SELF_REVIEW
          action: "Perform four passes: structure, concision, clarity (Falsifiability Standard), and navigation."
        - id: RUN_GATES
          action: "Execute REVIEW mode logic to verify the draft."
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
