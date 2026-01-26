# RFC Council Commands

commands[4]:
  - name: create
    command: "/rfc-council create PRD-XXXX"
    purpose: "Generate RFC and tickets from PRD."
  - name: review
    command: "/rfc-council review RFC-XXXX"
    purpose: "Consolidated review and refinement. Checks for existing evidence, runs gates, remediates MAJOR findings, and emits a new evidence bundle."
  - name: review-council
    command: "/rfc-council review RFC-XXXX --council"
    purpose: "Run full council review with 3 subagents (includes refinement)."
  - name: implicit-review
    command: "/rfc-council RFC-XXXX"
    purpose: "Runs the consolidated review mode for the given RFC."

---

## Usage Examples

### Create RFC from PRD

```bash
# Generate RFC-0010 from PRD-0005
/rfc-council create PRD-0005

# This will:
# 1. Read PRD-0005 files
# 2. Generate 9 RFC YAML files in documents/rfcs/RFC-0010/
# 3. Create ticket files in documents/work/tickets/
# 4. Run self-review
# 5. Commit and push
```

### Consolidated Review & Refinement

```bash
# Review and iteratively improve RFC-0009 tickets
/rfc-council review RFC-0009

# This will:
# 1. Check for pre-existing evidence bundles at evidence/rfc/RFC-0009/reviews/
# 2. Run all 7 gates
# 3. Apply remediations for BLOCKER/MAJOR findings
# 4. Re-run gates to verify fixes
# 5. Emit a NEW evidence bundle at evidence/rfc/RFC-0009/reviews/rfc_review_{timestamp}.yaml
```

### Council Review

```bash
# Full council review with 3 subagents and refinement
/rfc-council review RFC-0009 --council
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
| 3 | Aborted (timeout or budget exhausted) |
