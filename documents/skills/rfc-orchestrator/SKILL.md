---
name: rfc-orchestrator
description: Synchronous RFC orchestration with Opus-only agents and explicit process verification.
argument-hint: "<RFC-XXXX>"
disable-model-invocation: true
---

title: RFC Orchestrator (Synchronous Merge Loop)
protocol:
  id: RFC-ORCHESTRATOR
  version: 2.0.0
  type: executable_specification
  inputs[1]:
    - TARGET_RFC
  outputs[2]:
    - MergeLedger
    - DoneSignal

variables:
  TARGET_RFC: "$1"

references[6]:
  - path: "../../theory/glossary/glossary.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: references/orchestrator-loop.md
    purpose: "Main loop: dispatch, monitor, fix, repeat until merged."
  - path: references/commands.md
    purpose: "Command reference: ticket discovery, PR status, reviews, process management."
  - path: references/stop-conditions.md
    purpose: "Stop conditions: all merged, no unblocked, dirty main, auth failure."
  - path: references/governance-principles.md
    purpose: "Holonic laws and reasoning modes governing state transitions and failure handling."
  - path: documents/skills/modes-of-reasoning/assets/selector.json
    purpose: "Reasoning mode selection heuristics for different problem types."

decision_tree:
  entrypoint: ORCHESTRATE
  nodes[1]:
    - id: ORCHESTRATE
      action: invoke_reference
      reference: references/orchestrator-loop.md
