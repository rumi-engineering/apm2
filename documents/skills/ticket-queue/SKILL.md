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

references[10]:
  - path: references/ticket-queue-workflow.md
    purpose: "Decision tree: select ticket, dispatch implementer, loop."
  - path: references/commands.md
    purpose: "Command reference: RFC discovery, reviewer state, subagent logs."
  - path: "@documents/skills/modes-of-reasoning/artifacts/44-means-end-instrumental.json"
    purpose: "Mode #44: Means-End / Instrumental Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/47-planning-policy.json"
    purpose: "Mode #47: Planning / Policy Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/52-value-of-information.json"
    purpose: "Mode #52: Value-of-Information Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/75-meta-reasoning.json"
    purpose: "Mode #75: Meta-Reasoning"
  - path: "@documents/skills/modes-of-reasoning/artifacts/13-abductive.json"
    purpose: "Mode #13: Abductive (Hypothesis) Reasoning"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_01.md"
    purpose: "LAW-01: Loop Closure & Gated Promotion"
  - path: "@documents/skills/laws-of-holonic-agent-systems/references/law_02.md"
    purpose: "LAW-02: Observable Context Sufficiency"
  - path: "@documents/security/AGENTS.md"
    purpose: "Security Documentation"

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/ticket-queue-workflow.md