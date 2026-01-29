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
  # Stop Conditions (LAW-12: Bounded Search and Termination Discipline)
  # ============================================================================
  # Agent-native termination uses consumption-based and convergence-based
  # bounds, not wall-clock time. Time constraints are human-centric artifacts.
  stop_conditions:
    # Episode budget: sufficient for multi-phase RFC workflows
    max_episodes: 25

    # Resource budgets: hard consumption limits
    budget:
      tokens: 500000
      tool_calls: 500

    # Convergence detection: stall = failure to make progress
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

TASK:
Execute RFC Council workflows using CAC instruction specs stored in assets/.

INPUTS:
- Arguments: $ARGUMENTS
- Required files: assets/index.json and referenced instruction specs.

PROCEDURE:
1) Load assets/index.json.
2) Load the instruction.spec artifacts listed in the index.
3) Follow workflow ordering: workflow → mode → review rubric → council protocol, as applicable.
4) If any required instruction asset is missing, emit UNPLANNED_CONTEXT_READ.

OUTPUT:
- Follow the output contract specified by the instruction specs (evidence bundles, verdicts, tickets).

CONSTRAINTS:
- Deterministic gates run before LLM-assisted gates.
- Keep SKILL.md human-facing; JSON assets are the machine-native execution contracts.
