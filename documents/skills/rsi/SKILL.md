---
name: rsi
description: Recursive Skill Improvement - Protocol for evolving agent methodologies through self-observation and standard-refinement.
---

title: Recursive Skill Improvement (RSI)
protocol:
  id: RSI
  version: 2.0.0
  type: executable_specification
  inputs[0]: []
  outputs[2]:
    - WorkProduct
    - MethodologicalUpgrade

references[3]:
  - path: references/rsi-workflow.md
    purpose: "Primary decision tree: Execute, Observe, Refine, Codify."
  - path: references/path-cheat-sheet.md
    purpose: "Current repository sources of truth for core components."
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_01.md"
    purpose: "LAW-01: Loop Closure"

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/rsi-workflow.md
