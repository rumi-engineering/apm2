# RFC Council Commands

commands[7]:
  - name: create
    command: "/rfc-council create PRD-XXXX"
    purpose: "Generate RFC v0 (Discovery) from PRD."
  - name: evolve
    command: "/rfc-council RFC-XXXX"
    purpose: "Auto-advance RFC through lifecycle: v0 -> v2 (EXPLORE), v2 -> v4 (FINALIZE), v4 -> Tickets (DECOMPOSE)."
  - name: explore
    command: "/rfc-council explore RFC-XXXX"
    purpose: "Explicitly run EXPLORE mode to advance v0 -> v2 with codebase investigation."
  - name: finalize
    command: "/rfc-council finalize RFC-XXXX"
    purpose: "Explicitly run FINALIZE mode to advance v2 -> v4 with forced convergence."
  - name: review
    command: "/rfc-council review RFC-XXXX"
    purpose: "Consolidated review and refinement. Checks for existing evidence, runs gates, remediates MAJOR findings, and emits a new evidence bundle."
  - name: review-council
    command: "/rfc-council review RFC-XXXX --council"
    purpose: "Run full council review with 3 subagents (includes refinement)."
  - name: implicit-review
    command: "/rfc-council RFC-XXXX"
    purpose: "Runs the appropriate evolution or review mode based on target state."

---

## Usage Examples

### Lifecycle Progression

The RFC evolves through versioned phases. Each invocation advances to the next phase:

```bash
# 1. Initialize RFC v0 from PRD (GENESIS phase)
/rfc-council create PRD-0005
# Output: documents/rfcs/RFC-0010/ created with version: v0

# 2. Advance v0 -> v2 (EXPLORATION phase)
/rfc-council RFC-0010
# Performs codebase investigation, grounds design decisions
# Output: RFC-0010/00_meta.yaml updated to version: v2

# 3. Advance v2 -> v4 (CLOSURE phase)
/rfc-council RFC-0010
# Forces convergence on all open questions
# Output: RFC-0010/00_meta.yaml updated to version: v4

# 4. Generate Tickets from v4 (DECOMPOSITION phase)
/rfc-council RFC-0010
# Creates atomic engineering tickets
# Output: documents/work/tickets/TCK-*.yaml files
```

### Explicit Mode Selection

Override automatic mode selection when needed:

```bash
# Force EXPLORE mode on any RFC (useful for re-investigation)
/rfc-council explore RFC-0010

# Force FINALIZE mode (skip exploration if already grounded)
/rfc-council finalize RFC-0010
```

### Consolidated Review & Refinement

```bash
# Review and iteratively improve RFC-0009 tickets
/rfc-council review RFC-0009
```

---

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--council` | Enable 3-subagent council mode | false |
| `--depth STANDARD\|COUNCIL` | Set review depth | auto-computed |
| `--dry-run` | Show what would be done without changes | false |

---

## Output Files

| Mode | Output Path |
|------|-------------|
| create | `documents/rfcs/RFC-XXXX/`, `documents/work/tickets/TCK-*.yaml` |
| review | `evidence/rfc/RFC-XXXX/reviews/rfc_review_{timestamp}.yaml` |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (APPROVED or APPROVED_WITH_REMEDIATION) |
| 1 | Rejected (REJECTED verdict) |
| 2 | Needs human review (NEEDS_ADJUDICATION) |
| 3 | Aborted (budget or episode limit exhausted) |
