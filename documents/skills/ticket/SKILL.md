---
name: ticket
description: Orchestrate development work for an engineering ticket, with paths for new work or existing PR follow-up.
argument-hint: "[TCK-XXXXX | RFC-XXXX | empty]"
aliases: ["dev-eng-ticket"]
---

title: Engineering Ticket Workflow
protocol:
  id: TICKET
  version: 3.0.0
  type: executable_specification
  inputs[1]:
    - TICKET_ID_OPTIONAL
  outputs[2]:
    - WorktreePath
    - PR_URL

variables:
  TICKET_ID_OPTIONAL: "$1"

bootstrap:
  - step: "DISCOVER_CLI"
    action: "Run `apm2 fac --help` and read the output to discover available subcommands. Then run `apm2 fac <subcommand> --help` for each subcommand you will use during this workflow. Do NOT assume subcommand names or flag syntax — use the help output as the authoritative reference."
    when: "FIRST — before invoking any `apm2 fac` command."

notes:
  - "Required merge-gate context is `Review Gate Success`, bound to the current PR head SHA. Some repos/branches may still require additional legacy contexts (for example `CI Success`) until branch protection cutover is complete."
  - "Use `apm2 fac` commands as the primary operational interface for review lifecycle state (`apm2 fac review status`, `apm2 fac review project`, `apm2 fac review retrigger`)."
  - "Use direct `gh` workflow dispatch only as fallback when FAC projection commands are unavailable."
  - "Use `gh` for full comment body retrieval until equivalent `apm2` projection support is available."

references[20]:
  - path: "@documents/theory/glossary/glossary.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: references/ticket-workflow.md
    purpose: "Primary decision tree for new ticket vs existing PR follow-up."
  - path: references/commands.md
    purpose: "Command reference with flags and examples."
  - path: references/one-off-workflow.md
    purpose: "Ad-hoc ticket creation for urgent fixes or improvements outside the normal queue."
  - path: "@documents/skills/modes-of-reasoning/assets/07-type-theoretic.json"
    purpose: "Mode #07: Type-Theoretic Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/49-robust-worst-case.json"
    purpose: "Mode #49: Robust / Worst-Case Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/08-counterexample-guided.json"
    purpose: "Mode #08: Counterexample-Guided Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/65-deontic.json"
    purpose: "Mode #65: Deontic (Authority) Reasoning"
  - path: "@documents/skills/modes-of-reasoning/assets/80-debiasing-epistemic-hygiene.json"
    purpose: "Mode #80: Debiasing / Epistemic Hygiene"
  - path: "@documents/security/AGENTS.cac.json"
    purpose: "Security Documentation"
  - path: "@documents/skills/rust-standards/references/15_errors_panics_diagnostics.md"
    purpose: "RS-15: Errors, Panics, Diagnostics"
  - path: "@documents/skills/rust-standards/references/20_testing_evidence_and_ci.md"
    purpose: "RS-20: Testing Evidence and CI"
  - path: "@documents/skills/rust-standards/references/25_api_design_stdlib_quality.md"
    purpose: "RS-25: API Design"
  - path: "@documents/skills/rust-standards/references/27_collections_allocation_models.md"
    purpose: "RS-27: Collections and Allocation"
  - path: "@documents/skills/rust-standards/references/30_paths_filesystem_os.md"
    purpose: "RS-30: Paths and Filesystem"
  - path: "@documents/skills/rust-standards/references/31_io_protocol_boundaries.md"
    purpose: "RS-31: I/O and Protocol Boundaries"
  - path: "@documents/skills/rust-standards/references/34_security_adjacent_rust.md"
    purpose: "RS-34: Security-Adjacent Rust"
  - path: "@documents/skills/rust-standards/references/39_hazard_catalog_checklists.md"
    purpose: "RS-39: Hazard Catalog"
  - path: "@documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md"
    purpose: "RS-41: Safe Patterns"

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/ticket-workflow.md
