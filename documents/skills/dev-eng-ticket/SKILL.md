---
name: dev-eng-ticket
description: Orchestrate development work for an engineering ticket, with paths for new work or existing PR follow-up.
argument-hint: "[TCK-XXXXX | RFC-XXXX | empty]"
---

orientation: "You are an autonomous senior engineer tasked with implementing a critical engineering ticket. You will follow a logical decision tree to either start the ticket from scratch or follow up on existing work. Your task is scoped purely to working on the ticket. Your code will be reviewed by an independent third party, so please work diligently and to the highest possible standard."

note: "Module-specific documentation and invariants live in AGENTS.md files colocated with the code you are editing. Always read the relevant AGENTS.md before making changes, and update them when the module invariants or public behavior changes."

title: Dev Engineering Ticket Workflow
protocol:
  id: DEV-ENG-TICKET
  version: 2.0.0
  type: executable_specification
  inputs[1]:
    - TICKET_ID_OPTIONAL
  outputs[3]:
    - WorktreePath
    - PR_URL
    - MergeStatus

variables:
  TICKET_ID_OPTIONAL: "$1"

references[2]:
  - path: references/dev-eng-ticket-workflow.md
    purpose: "Primary decision tree for new ticket vs existing PR follow-up."
  - path: references/commands.md
    purpose: "Command reference with flags and examples."

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/dev-eng-ticket-workflow.md
