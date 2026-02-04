---
name: ticket-queue
description: Orchestrate ticket processing until all `documents/work/tickets/TCK-*.yaml` are merged to `main`.
argument-hint: "[RFC-XXXX]"
disable-model-invocation: true
---

title: Ticket Queue (Sequential Merge Orchestration)
protocol:
  id: TICKET-QUEUE
  version: 1.1.0
  type: executable_specification
  inputs[1]:
    - TARGET_RFC
  outputs[3]:
    - TicketMergeLedger
    - BlockerReport
    - DoneSignal

variables:
  TARGET_RFC: "$1"

references[11]:
  - path: "@documents/theory/glossary/glossary.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: references/ticket-queue-workflow.md
    purpose: "Decision tree: select ticket, dispatch implementer, loop."
  - path: references/commands.md
    purpose: "Command reference: RFC discovery, reviewer state, subagent logs."
  - path: "@documents/skills/modes-of-reasoning/assets/44-means-end-instrumental.json"
    purpose: "Mode #44: Means-End / Instrumental Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/47-planning-policy.json"
    purpose: "Mode #47: Planning / Policy Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/52-value-of-information.json"
    purpose: "Mode #52: Value-of-Information Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/75-meta-reasoning.json"
    purpose: "Mode #75: Meta-Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/13-abductive.json"
    purpose: "Mode #13: Abductive (Hypothesis) Reasoning"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-01: Loop Closure & Gated Promotion"
  - path: "@documents/theory/laws.json"
    purpose: "LAW-02: Observable Context Sufficiency"
  - path: "@documents/security/AGENTS.md"
    purpose: "Security Documentation"

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/ticket-queue-workflow.md