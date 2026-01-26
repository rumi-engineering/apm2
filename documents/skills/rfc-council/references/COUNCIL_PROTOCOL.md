title: RFC COUNCIL Protocol

decision_tree:
  entrypoint: COUNCIL_ORCHESTRATION
  nodes[1]:
    - id: COUNCIL_ORCHESTRATION
      purpose: "Orchestrate 3-agent deliberation for RFC tickets."
      steps[1]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <RFC_ID> placeholders before running commands."

## Overview

The COUNCIL protocol is a multi-agent deliberation process designed to prevent "cognitive entropy collapse" (premature convergence on suboptimal designs). It achieves this by:
1. Spawns 3 subagents with specialized but lifecycle-adaptive roles.
2. **Maximum Entropy Reasoning:** Each subagent selects **5 strictly random reasoning modes** from `modes-of-reasoning/SKILL.md`. By removing fixed "specialized" modes, the council is forced to synthesize new perspectives for every session, preventing model-mode entrenchment.
3. Subagents apply Agent-Native Software principles (Stochastic Cognition, Tool-Loops) to their analysis.
4. Subagents execute 3 review cycles with inter-cycle onboarding notes.
5. Findings converge through quorum voting (2/3 agreement).

---

## State Machine

[... existing state machine ...]

---

## INIT Phase

### Step 1: Session Initialization

[... existing initialization steps ...]

### Step 2: Spawn Subagents (Lifecycle-Aware)

Spawn 3 subagents. Their specific focus shifts based on the RFC version:

| Agent | v0 (Discovery) Focus | v2 (Exploration) Focus | v4 (Closure) Focus |
|-------|----------------------|------------------------|--------------------|
| SA-1  | Structural mapping, PRD fidelity | Codebase pattern alignment | Final architectural convergence |
| SA-2  | Risk identification, knowledge gaps | Mock implementation runs | Execution efficiency & atomicity |
| SA-3  | Trust boundary discovery | Extension point security | Final security assurance (CAE Tree) |

### Step 3: Stochastic Mode Selection

Each subagent selects **5 strictly random modes** from `documents/skills/modes-of-reasoning/SKILL.md`.

**Constraint:** Subagents must explain how their 5 random modes interact to challenge their primary lifecycle focus. For example, SA-1 (Structural Rigorist) might be forced to use Mode 24 (Heuristic) or Mode 62 (Historical), "disturbing" their usual deductive patterns.

Despite the randomness of the reasoning *lens*, subagents must still produce their assigned artifacts by applying their random modes to the task:

#### SA-1: Efficacy & Structure Rigorist
- Artifact: **Explanatory Scoring Table** (Evaluating chosen design vs. alternatives through the 5 random lenses).

#### SA-2: Implementation Feasibility
- Artifact: **Mock Implementation Run Report** (Simulating agent logic using the 5 random lenses to identify friction points).

#### SA-3: Security & Anti-Cousin Guardian
- Artifact: **Claim-Argument-Evidence (CAE) Tree** (Building security assurance by justifying claims using the 5 random lenses).

### Step 4: Validate Mode Selection

Before proceeding to CYCLE_1:
- [ ] Each subagent has exactly 5 strictly random modes.
- [ ] Total mode overlap across all subagents is minimized.
- [ ] Each subagent has modes from >= 2 categories in the reasoning taxonomy.

---

## CYCLE_1: STRUCTURAL

**Purpose:** Validate structural properties. Execute deterministic gates.

### Gates Executed

1. GATE-TCK-SCHEMA
2. GATE-TCK-DEPENDENCY-ACYCLICITY
3. GATE-TCK-SCOPE-COVERAGE
4. GATE-TCK-CCP-MAPPING

### Execution

For each subagent:
1. Load RFC and ticket files
2. For each assigned gate:
   a. Apply the 5 random modes of reasoning to the structural analysis.
   b. Generate findings using those lenses.
   c. Tag each finding with `source_mode` and `source_agent`.
3. Record all findings in session state.

### Cycle 1 Output Requirements

Each subagent produces:
- 0-N findings.
- Each finding MUST include:
  - `source_agent`: SA-1, SA-2, or SA-3.
  - `source_cycle`: 1.
  - `source_mode`: which of the 5 random modes generated it.
  - `agreement_status`: PENDING.

[... rest of protocol ...]

### Aggregation

After all subagents complete:
1. Merge findings, deduplicate by signature
2. For each finding, check if multiple subagents raised it:
   - If raised by >=2 subagents: `agreement_status: MAJORITY`
   - If raised by all 3: `agreement_status: UNANIMOUS`
   - If raised by only 1: `agreement_status: PENDING`
3. Identify contested items (conflicting assessments)

### Onboarding Note Generation

Generate onboarding notes for Cycle 2:

```yaml
focus_areas:
  - Structural blockers found
  - CCP mapping gaps
  - Dependency issues

gate_results:
  - gate_id: GATE-TCK-SCHEMA
    status: PASSED | FAILED
    finding_count: N

contested_items:
  - Items where subagents disagree
```

---

## CYCLE_2: FEASIBILITY

**Purpose:** Assess implementability and atomicity. Execute LLM-assisted gates.

### Gates Executed

5. GATE-TCK-ATOMICITY
6. GATE-TCK-IMPLEMENTABILITY
7. GATE-TCK-ANTI-COUSIN

### Pre-Cycle Loading

Each subagent loads:
- Cycle 1 onboarding notes
- Merged findings from Cycle 1
- Contested items list

### Execution

For each subagent:
1. Review Cycle 1 findings
2. For each LLM-assisted gate:
   a. Apply relevant modes to assess tickets
   b. For SA-2: Focus on agent theory-of-mind
   c. For SA-3: Focus on CCP alignment
3. Generate new findings
4. Propose remediations for BLOCKER/MAJOR findings

### Cycle 2 Output Requirements

Each subagent produces:
- Gate assessments for ATOMICITY, IMPLEMENTABILITY, ANTI-COUSIN
- Remediation proposals for BLOCKER/MAJOR findings
- Updated agreement_status for contested items

### Aggregation

After all subagents complete:
1. Merge new findings
2. For contested items, tally support/dissent
3. Identify items still contested

### Onboarding Note Generation

Generate onboarding notes for Cycle 3:

```yaml
focus_areas:
  - Items requiring quorum vote
  - Remaining BLOCKER findings without remediation

convergence_targets:
  - Specific findings to resolve in Cycle 3

consensus_candidates:
  - Findings with majority agreement (ready for quorum)
```

---

## CYCLE_3: CONVERGE

**Purpose:** Reach consensus. Vote on contested findings using 2/3 quorum.

### Pre-Cycle Loading

Each subagent loads:
- Cycle 2 onboarding notes
- Current state of all findings
- Contested items requiring resolution

### Execution

For each contested finding:
1. Each subagent casts vote: SUPPORT or OPPOSE
2. Optionally provide final rationale
3. If 2/3 (2 of 3) agree: finding status = RESOLVED
4. If not: finding status = DEADLOCKED

For each unresolved BLOCKER:
1. Final attempt to propose remediation
2. If no remediation possible: escalate to NEEDS_ADJUDICATION

### Quorum Rules

```python
def apply_quorum(finding, votes):
    support_count = sum(1 for v in votes if v == "SUPPORT")
    oppose_count = sum(1 for v in votes if v == "OPPOSE")

    if support_count >= 2:
        finding.agreement_status = "QUORUM_SUPPORT"
        finding.in_consensus = True
    elif oppose_count >= 2:
        finding.agreement_status = "QUORUM_OPPOSE"
        finding.in_consensus = False
    else:
        finding.agreement_status = "DEADLOCKED"
        # Escalate to DEADLOCKED terminal state
```

---

## Terminal States

### CONVERGED

Conditions:
- All BLOCKER findings resolved (remediated or dismissed by quorum)
- Quorum achieved on all contested findings

Outputs:
- `verdict`: Based on remaining findings
- `consensus_findings`: All findings with quorum agreement
- `council_metadata`: Session statistics

### DEADLOCKED

Conditions:
- Quorum failed on >=1 contested finding after Cycle 3
- OR: BLOCKER finding unresolved with no remediation consensus

Outputs:
- `verdict`: NEEDS_ADJUDICATION
- `deadlocked_findings`: Findings that failed quorum
- `escalation_target`: Human review required

### ABORTED

Conditions:
- Session duration exceeds 1 hour
- OR: Token budget exhausted

Outputs:
- `verdict`: ABORTED
- `partial_findings`: All findings generated before abort
- `abort_reason`: TIMEOUT or BUDGET_EXHAUSTED
- `cycles_completed`: How many cycles finished

---

## Evidence Bundle Output

Council sessions produce an enhanced evidence bundle:

```yaml
schema_version: "1.0.0"
rfc_id: RFC-XXXX
review_timestamp: "2026-01-26T10:00:00Z"
review_depth: COUNCIL

gates: [...]
findings: [...]
verdict: APPROVED
verdict_reason: "Council reached consensus"

council_metadata:
  session_id: COUNCIL-RFC-XXXX-20260126-100000
  subagents:
    - agent_id: SA-1
      emergent_role: Structural Rigorist
      selected_modes: [1, 6, 7, 43, 75]
    - agent_id: SA-2
      emergent_role: Implementation Feasibility
      selected_modes: [47, 48, 51, 56, 70]
    - agent_id: SA-3
      emergent_role: Anti-Cousin Guardian
      selected_modes: [14, 15, 32, 33, 79]
  cycles_completed: 3
  total_findings_generated: 24
  findings_after_dedup: 15
  contested_items_resolved: 4
  quorum_achieved: true
  elapsed_time_seconds: 1847
```

---

## Timeout and Budget

### Timeout

- Default: 1 hour (3600 seconds)
- Measured from INIT to terminal state
- On timeout: Abort with partial findings

### Token Budget

- Estimated budget: ~150K tokens per council session
- Monitor cumulative usage across all subagents
- On budget exhaustion: Abort with partial findings

### Budget Allocation

Approximate allocation per cycle:
- INIT + Mode Selection: ~5K tokens
- CYCLE_1 (STRUCTURAL): ~40K tokens
- CYCLE_2 (FEASIBILITY): ~50K tokens
- CYCLE_3 (CONVERGE): ~40K tokens
- Final assembly: ~15K tokens

---

## Error Handling

### Subagent Failure

If a subagent fails during any cycle:
1. Log failure reason
2. Continue with remaining subagents
3. Adjust quorum requirement (2/2 if one fails)
4. Note degraded mode in final bundle

### Convergence Failure

If Cycle 3 fails to reach quorum:
1. Record deadlocked findings
2. Emit partial consensus
3. Set verdict to NEEDS_ADJUDICATION
