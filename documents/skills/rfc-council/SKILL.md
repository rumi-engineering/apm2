---
name: rfc-council
description: Unified skill for RFC creation and ticket quality review with multi-agent council deliberation and anti-cousin enforcement.
argument-hint: "[create | review] [PRD-XXXX | RFC-XXXX]"
user-invocable: true
holon:
  # ============================================================================
  # Contract Definition
  # ============================================================================
  contract:
    input_type: RfcCouncilRequest
    output_type: RfcCouncilResult
    state_type: RfcCouncilProgress

  # ============================================================================
  # Stop Conditions
  # ============================================================================
  stop_conditions:
    # Maximum episodes: RFC work involves multiple phases
    #   - CREATE mode: RFC generation + ticket decomposition ~ 15-20 episodes
    #   - REVIEW mode: Consolidated review + remediation ~ 20-25 episodes
    max_episodes: 25

    # Timeout: 30 minutes for complete RFC operations
    timeout_ms: 1800000

    # Budget limits
    budget:
      tokens: 500000
      tool_calls: 500

    # Stall detection
    max_stall_episodes: 5

  # ============================================================================
  # Tool Permissions
  # ============================================================================
  tools:
    - Read         # Read RFCs, tickets, CCP, codebase files
    - Write        # Create RFC YAML files and ticket files
    - Edit         # Modify RFC/ticket files during review
    - Glob         # Find files by pattern
    - Grep         # Search file contents
    - Bash         # Git operations, mkdir
    - Task         # Spawn subagents for council deliberation
---

orientation: "You are an RFC Council agent. Your job is to ensure that engineering tickets derived from RFCs are (a) structurally sound, (b) implementation-ready for other agents, and (c) architecturally compliant (no cousin abstractions). You orchestrate multi-agent deliberations for complex system-wide changes to maintain the North Star vision. Replaces the deprecated `create-rfc` skill."

title: RFC Council & Ticket Review
protocol:
  id: RFC-COUNCIL
  version: 1.0.0
  type: executable_specification
  inputs[2]:
    - MODE_OPTIONAL
    - TARGET_ID
  outputs[2]:
    - FindingsBundle
    - Verdict

variables:
  MODE_OPTIONAL: "$1"
  TARGET_ID: "$2"

references[9]:
  - path: references/rfc-council-workflow.md
    purpose: "Primary decision tree for mode selection and input validation."
  - path: references/create-mode.md
    purpose: "Logic for generating RFC and tickets from PRD."
  - path: references/review-mode.md
    purpose: "Logic for formal ticket review and depth computation (includes refinement)."
  - path: references/REVIEW_RUBRIC.md
    purpose: "Formal gate definitions and evidence contracts."
  - path: references/FINDING_CATEGORIES.md
    purpose: "Deterministic finding taxonomy and severity rules."
  - path: references/COUNCIL_PROTOCOL.md
    purpose: "Multi-agent deliberation protocol for COUNCIL reviews."
  - path: references/commands.md
    purpose: "CLI command reference."
  - path: ../agent-native-software/SKILL.md
    purpose: "REQUIRED READING: First principles of agent-native software engineering."
  - path: ../../security/AGENTS.md
    purpose: "REQUIRED READING: Security policy, threat models, and incident response."

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/rfc-council-workflow.md

# RFC Council Skill

Orchestrates RFC creation and ticket quality review with multi-agent council deliberation and
anti-cousin enforcement.

## Prerequisites

1. **CCP Required**: Codebase Context Pack must exist at `evidence/prd/{PRD_ID}/ccp/` (CREATE)
   or be referenced by RFC (REVIEW)
2. **Input**: PRD-XXXX (CREATE) or RFC-XXXX (REVIEW) must exist
3. **Required Reading**: Load `agent-native-software` skill and `AGENTS.md` security policy

## Modes

| Mode | Input | Output | Version Transition | Purpose |
|------|-------|--------|-------------------|---------|
| CREATE | PRD-XXXX | RFC v0 | - -> v0 | Generate discovery-focused RFC v0 from PRD |
| EXPLORE | RFC v0 | RFC v2 | v0 -> v2 | Codebase investigation to resolve open questions |
| FINALIZE | RFC v2 | RFC v4 | v2 -> v4 | Final architectural convergence and sign-off |
| DECOMPOSE| RFC v4 | Tickets | v4 -> Tickets | Generate implementation-ready engineering tickets |
| REVIEW | RFC-XXXX | Findings | (any) | Formal gate review with iterative refinement |

### Automatic Mode Selection

When invoked with just an RFC ID (e.g., `/rfc-council RFC-0010`), the skill auto-selects the appropriate mode based on the RFC version in `00_meta.yaml`:

```
RFC v0  -> EXPLORE mode  (advance to v2)
RFC v2  -> FINALIZE mode (advance to v4)
RFC v4  -> DECOMPOSE mode (generate tickets)
```

This enables a simple progression: invoke `/rfc-council RFC-XXXX` repeatedly to advance the RFC through its lifecycle.

## Council Evolution Phases

The RFC lifecycle progresses through versioned phases, each with distinct goals and council focus:

| Phase | Version | Council Focus | Key Artifacts |
|-------|---------|---------------|---------------|
| **GENESIS** | v0 | Map PRD to architecture; identify "Known Unknowns" | `08_risks_and_open_questions.yaml` populated |
| **EXPLORATION** | v0 -> v2 | Codebase deep-dive; anchor design in existing patterns | `02_design_decisions.yaml` grounded in evidence |
| **CLOSURE** | v2 -> v4 | Forced convergence; defer or answer all open questions | All placeholders resolved; gates pass |
| **DECOMPOSITION** | v4 | Create atomic, agent-executable engineering tickets | `documents/work/tickets/TCK-*.yaml` created |

### Phase Progression Rules

1. **v0 (Discovery)**: RFC created from PRD. Open questions documented but not necessarily resolved.
2. **v2 (Grounded)**: Codebase investigation complete. Design decisions backed by evidence.
3. **v4 (Standard)**: All open questions resolved or explicitly deferred. Ready for ticket decomposition.

Each phase transition requires passing relevant gates:
- **v0 -> v2**: GATE-TCK-CCP-MAPPING (verify codebase alignment)
- **v2 -> v4**: All 9 gates must pass (APPROVED or APPROVED_WITH_REMEDIATION)
- **v4 -> Tickets**: GATE-TCK-ATOMICITY and GATE-TCK-IMPLEMENTABILITY for each ticket

## Gate Structure

| Gate | Type | Purpose |
|------|------|---------|
| GATE-TCK-SCHEMA | TRUSTED | YAML parsing |
| GATE-TCK-DEPENDENCY-ACYCLICITY | DETERMINISTIC | No cycles |
| GATE-TCK-SCOPE-COVERAGE | DETERMINISTIC | Requirements covered |
| GATE-TCK-CCP-MAPPING | DETERMINISTIC | Files exist in CCP |
| GATE-TCK-ATOMICITY | LLM-ASSISTED | Single-PR completable |
| GATE-TCK-IMPLEMENTABILITY | LLM-ASSISTED | Agent can implement |
| GATE-TCK-ANTI-COUSIN | LLM-ASSISTED | No cousin abstractions |

## Council Subagents

| Agent | Role | Focus |
|-------|------|-------|
| SA-1 | Structural Rigorist | Dependencies, type safety |
| SA-2 | Implementation Feasibility | Execution planning |
| SA-3 | Anti-Cousin Guardian | CCP alignment, reuse |

## Review Cycles

1. **CYCLE_1 (STRUCTURAL)**: Schema, dependencies, coverage, CCP mapping
2. **CYCLE_2 (FEASIBILITY)**: Atomicity, implementability, anti-cousin
3. **CYCLE_3 (CONVERGE)**: 2/3 quorum vote on contested findings

## Holon Configuration

### Stop Conditions

| Condition | Value | Rationale |
|-----------|-------|-----------|
| max_episodes | 25 | Multi-phase RFC work |
| timeout_ms | 1,800,000 | 30 minutes |
| budget.tokens | 500,000 | Token limit |
| budget.tool_calls | 500 | Tool limit |
| max_stall_episodes | 5 | Stall detection |

### Tool Permissions

- `Read` - Read RFCs, tickets, CCP, codebase
- `Write` - Create RFC/ticket files
- `Edit` - Modify during review
- `Glob` - Find files
- `Grep` - Search contents
- `Bash` - Git operations
- `Task` - Spawn subagents

PRD-0005 Alignment

The ## Prerequisites section documents CCP as mandatory input, aligning with PRD-0005's core
requirement. The ## Gate Structure includes GATE-TCK-CCP-MAPPING for anti-cousin enforcement.

## Verdict Rules

- **APPROVED**: All gates passed, zero BLOCKER/MAJOR findings.
- **APPROVED_WITH_REMEDIATION**: All gates passed, 1-3 MAJOR findings with fixes.
- **REJECTED**: Any gate failed OR >3 MAJOR findings.
- **NEEDS_ADJUDICATION**: Council deadlocked on a critical finding or confidence is LOW.

## Success Metrics

- **First-pass success rate**: >=80% (Tickets merged without rework)
- **Rework rate**: <=15% (Tickets requiring revision)
- **Anti-cousin compliance**: >=95% (Tickets with no COUSIN findings)
- **Dependency accuracy**: >=90% (Tickets without blocked merges)

## North Star Alignment

This protocol directly serves **Phase 1 (Recursive Self-Improvement)** by:
- Enabling agent autonomy through implementable tickets.
- Preventing architectural debt via anti-cousin discipline.
- Improving first-pass success rate to reduce human intervention.
- Ensuring atomic tickets enable parallel agent execution.
