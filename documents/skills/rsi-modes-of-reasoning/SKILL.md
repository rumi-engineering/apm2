---
name: rsi-modes-of-reasoning
description: Recursive Skill Improvement for modes-of-reasoning artifacts. Improves density, clarity, and actionability of reasoning mode documentation.
user-invocable: true
argument-hint: "[<mode-number> | <mode-name> | <file-path> | empty]"
---

title: RSI Modes-of-Reasoning
protocol:
  id: RSI-MOR
  version: 1.0.0
  type: executable_specification
  inputs[1]:
    - TARGET_OR_EMPTY
  outputs[2]:
    - ImprovedArtifact
    - Changelog

variables:
  TARGET_OR_EMPTY: "$1"

references[3]:
  - path: references/rsi-modes-workflow.md
    purpose: "Primary decision tree for selection, diagnosis, and refinement."
  - path: "@documents/skills/modes-of-reasoning/artifacts/selector.json"
    purpose: "Source of truth for mode taxonomy and category mappings."
  - path: "@documents/skills/modes-of-reasoning/SKILL.md"
    purpose: "Skill definition and quick reference table."

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/rsi-modes-workflow.md