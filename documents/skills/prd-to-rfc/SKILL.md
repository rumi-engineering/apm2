---
name: prd-to-rfc
description: End-to-end orchestrator that compiles a PRD into an approved RFC with tickets. Invokes rfc-council create, then iteratively reviews until APPROVED or stop conditions met.
argument-hint: "PRD-XXXX [--max-iterations N] [--council] [--dry-run]"
user-invocable: true
holon:
  # ============================================================================
  # Contract Definition
  # ============================================================================
  contract:
    input_type: PrdToRfcRequest
    output_type: PrdToRfcResult
    state_type: PrdToRfcProgress

  # ============================================================================
  # Stop Conditions
  # ============================================================================
  stop_conditions:
    max_episodes: 50
    timeout_ms: 3600000
    budget:
      tokens: 1000000
      tool_calls: 1000
    max_stall_episodes: 5

  # ============================================================================
  # Tool Permissions
  # ============================================================================
  tools:
    - Read           # Read PRD, RFC, CCP, evidence files
    - Write          # Create orchestration evidence bundles
    - Edit           # Modify files during orchestration
    - Glob           # Find files by pattern
    - Grep           # Search file contents
    - Bash           # Git operations, mkdir
    - Task           # Spawn subagents for parallelization
    - Skill          # Required to invoke /rfc-council
---

orientation: "You are a PRD-to-RFC orchestrator. Your job is to take a PRD and guide it through the full RFC creation and approval pipeline by invoking the rfc-council skill iteratively until the RFC achieves APPROVED status or a terminal condition is reached."

title: PRD to RFC Orchestrator
protocol:
  id: PRD-TO-RFC
  version: 1.1.0
  type: executable_specification
  inputs[1]:
    - PRD_ID
  outputs[2]:
    - OrchestrationEvidence
    - FinalVerdict

variables:
  PRD_ID: "$1"
  MAX_ITERATIONS: "5"
  COUNCIL_FLAG: "false"
  DRY_RUN: "false"

references[6]:
  - path: ../../theory/glossary/glossary.json
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: references/prd-to-rfc-workflow.md
    purpose: "Primary decision tree for orchestration flow."
  - path: references/commands.md
    purpose: "CLI command reference."
  - path: ../rfc-council/SKILL.md
    purpose: "Underlying skill for RFC creation and review."
  - path: ../agent-native-software/SKILL.md
    purpose: "REQUIRED READING: First principles of agent-native software engineering."
  - path: ../../security/AGENTS.md
    purpose: "REQUIRED READING: Security policy, threat models, and incident response."

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/prd-to-rfc-workflow.md

## Verdict Rules

- **APPROVED**: RFC achieved APPROVED status.
- **APPROVED_WITH_REMEDIATION**: RFC achieved APPROVED_WITH_REMEDIATION status.
- **REJECTED**: Hit terminal rejection or MAX_ITERATIONS without success.
- **NEEDS_ADJUDICATION**: Underlying council deadlocked or confidence is LOW.
- **FAILED**: Orchestration failed due to missing prerequisites (PRD, CCP).

## Prerequisites

1. **PRD Required**: PRD must exist at `documents/prds/{PRD_ID}/`
2. **CCP Required**: Codebase Context Pack must exist at `evidence/prd/{PRD_ID}/ccp/`
3. **Required Reading**: Load `agent-native-software` skill and `AGENTS.md` security policy

## Workflow Summary

1. **VALIDATE**: Verify PRD and CCP existence. Check for existing RFC.
2. **CREATE**: If no RFC exists, invoke `/rfc-council create {PRD_ID}`.
3. **REVIEW LOOP**: Iteratively invoke `/rfc-council review {RFC_ID}` (optionally with `--council`).
4. **EMIT**: Generate final orchestration evidence bundle and commit results.

## Terminal Conditions

| Condition | Action |
|-----------|--------|
| APPROVED | Success, emit evidence bundle |
| APPROVED_WITH_REMEDIATION | Success, emit evidence bundle |
| NEEDS_ADJUDICATION | Escalate immediately |
| MAX_ITERATIONS_EXCEEDED | Escalate with iteration history |
| PRD_NOT_FOUND | Stop with FAILED status |
| CCP_REQUIRED | Stop with FAILED status |

## Success Metrics

- **End-to-end success rate**: >=75% (PRDs that achieve APPROVED)
- **Iteration efficiency**: <=3 average iterations to approval
- **Escalation rate**: <=10% (PRDs requiring human adjudication)

## Meta-Orchestration Protocol

Use Gemini to monitor the stability of the orchestration loop. If the same `FindingSignature` from `rfc-council` persists across 3 consecutive iterations without remediation, trigger `STALL_DETECTION`. This prevents "Infinite Loops" and ensures the orchestrator escalates `NEEDS_ADJUDICATION` when the automated refinement reaches its theoretical limit.

## North Star Alignment

This orchestrator directly serves **Phase 1 (Recursive Self-Improvement)** by:
- Automating the full PRD-to-RFC pipeline for agent autonomy
- Reducing human intervention through iterative refinement
- Ensuring quality gates are consistently applied
- Providing complete audit trail via evidence bundles
