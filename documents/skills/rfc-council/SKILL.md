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
