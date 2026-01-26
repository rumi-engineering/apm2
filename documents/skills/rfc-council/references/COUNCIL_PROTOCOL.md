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

The COUNCIL protocol is a multi-agent deliberation process that:
1. Spawns 3 subagents with specialized roles
2. Each subagent selects 5 reasoning modes from the 80 available
3. Subagents execute 3 review cycles with inter-cycle onboarding notes
4. Findings converge through quorum voting (2/3 agreement)
5. Final assessment includes implementability scoring

---

## State Machine

```
+---------+
|  INIT   | -- Initialize session, spawn subagents, select modes
+----+----+
     |
     v
+---------+
| CYCLE_1 | -- STRUCTURAL: Schema, dependencies, coverage, CCP
|(STRUCT) |
+----+----+
     | Generate onboarding notes
     v
+---------+
| CYCLE_2 | -- FEASIBILITY: Atomicity, implementability, anti-cousin
| (FEAS)  |
+----+----+
     | Generate onboarding notes
     v
+---------+
| CYCLE_3 | -- CONVERGE: Vote on contested findings, reach quorum
|(CONVERGE)|
+----+----+
     |
     v
   +-+-+
   |   |
   v   v
+------+ +----------+ +---------+
|CONVERGED| |DEADLOCKED| | ABORTED |
+------+ +----------+ +---------+
```

### State Transitions

| From | To | Trigger |
|------|----|---------|
| INIT | CYCLE_1 | All 3 subagents have selected 5 modes |
| CYCLE_1 | CYCLE_2 | All subagents completed structural review |
| CYCLE_2 | CYCLE_3 | All subagents completed feasibility review |
| CYCLE_3 | CONVERGED | All blockers resolved AND quorum achieved |
| CYCLE_3 | DEADLOCKED | Quorum failed on >=1 contested finding |
| ANY | ABORTED | Timeout (1 hour) OR budget exhausted |

---

## INIT Phase

### Step 1: Session Initialization

```yaml
session_id: "COUNCIL-{RFC_ID}-{timestamp}"
state: "INIT"
```

1. Create session file at `evidence/rfc/{RFC_ID}/reviews/council_session_{timestamp}.yaml`
2. Load RFC content and tickets into context
3. Load CCP component atlas
4. Load REQUIRED READING into context:
   - `documents/skills/agent-native-software/SKILL.md`
   - `documents/security/AGENTS.md`

### Step 2: Spawn Subagents

Spawn 3 subagents with specialized roles:

| Agent | Role | Focus | Key Modes |
|-------|------|-------|-----------|
| SA-1 | Structural Rigorist | Graph properties, dependencies | 1 (Deductive), 6 (Constraint), 7 (Type-theoretic), 43 (Systems), 75 (Meta) |
| SA-2 | Implementation Feasibility | Agent theory-of-mind, execution | 47 (Planning), 48 (Optimization), 51 (Satisficing), 56 (Theory-of-mind), 70 (Engineering) |
| SA-3 | Anti-Cousin Guardian | CCP alignment, reuse validation | 14 (Analogical), 15 (Case-based), 32 (Defeasible), 33 (Belief revision), 79 (Adversarial) |

### Step 3: Mode Selection

Each subagent selects 5 modes based on their specialization:

#### SA-1: Structural Rigorist
- Mode 1 (Deductive): Formal validation of dependency graph
- Mode 6 (Constraint): Schema and structural constraints
- Mode 7 (Type-theoretic): Type safety in interfaces
- Mode 43 (Systems): Cross-component interactions
- Mode 75 (Meta): Reasoning about review process

#### SA-2: Implementation Feasibility
- Mode 47 (Planning): Implementation step completeness
- Mode 48 (Optimization): Resource efficiency
- Mode 51 (Satisficing): Acceptable vs optimal solutions
- Mode 56 (Theory-of-mind): Agent implementability
- Mode 70 (Engineering): Practical implementation concerns

#### SA-3: Anti-Cousin Guardian
- Mode 14 (Analogical): Pattern matching to existing code
- Mode 15 (Case-based): Historical precedent
- Mode 32 (Defeasible): Reuse assumptions
- Mode 33 (Belief revision): Updating CCP knowledge
- Mode 79 (Adversarial): Red-teaming reuse claims

### Step 4: Validate Mode Selection

Before proceeding to CYCLE_1:
- [ ] Each subagent has exactly 5 modes
- [ ] At least one subagent has a mode in range 75-80 (SA-1 has 75)
- [ ] Total mode overlap <= 5 across all subagents
- [ ] Each subagent has modes from >= 3 categories

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
   a. Apply mode-specific reasoning
   b. Generate findings using that mode's lens
   c. Tag each finding with `source_mode` and `source_agent`
3. Record all findings in session state

### Cycle 1 Output Requirements

Each subagent produces:
- 0-N findings (no minimum, no maximum)
- Each finding MUST include:
  - `source_agent`: SA-1, SA-2, or SA-3
  - `source_cycle`: 1
  - `source_mode`: which of the 5 modes generated it
  - `agreement_status`: PENDING

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
