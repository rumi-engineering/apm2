title: RSI Protocol Workflow

decision_tree:
  entrypoint: EXECUTE_AND_OBSERVE
  nodes:
    - id: EXECUTE_AND_OBSERVE
      purpose: "Perform the primary task while logging methodological friction."
      steps:
        - id: TASK_EXECUTION
          action: "Execute the assigned work product (code, docs, PR) to existing standards."
        - id: FRICTION_LOGGING
          action: "Maintain a log of: ambiguity in instructions, tool inefficiency, or missing context."
      next_node: REFINE_AND_CODIFY

    - id: REFINE_AND_CODIFY
      purpose: "Upgrade the methodology and update the Path Cheat Sheet."
      steps:
        - id: METHODOLOGY_UPGRADE
          action: "Update the relevant SKILL.md or reference file to resolve logged friction."
        - id: PATH_CODIFICATION
          action: "If new 'Sources of Truth' were found, update the Path Cheat Sheet in RSI SKILL.md."
      next_node: GLOSSARY_SHARPENING

    - id: GLOSSARY_SHARPENING
      purpose: "Enforce normative standards on any new glossary/term definitions."
      if: "Task involves defining or updating terms"
      steps:
        - id: LAYER_1_PROTO
          action: "Link to protobuf messages in `proto/`."
        - id: LAYER_2_ERROR
          action: "Link to relevant Error enums in `apm2-core`."
        - id: LAYER_3_LIFECYCLE
          action: "State tool-to-reducer persistence lifecycle."
