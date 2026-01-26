# RFC Council Commands

commands[5]:
  - name: create
    command: "/rfc-council create PRD-XXXX"
    purpose: "Generate RFC and tickets from PRD."
  - name: review
    command: "/rfc-council review RFC-XXXX"
    purpose: "Review RFC tickets and emit findings (no edits)."
  - name: review-council
    command: "/rfc-council review RFC-XXXX --council"
    purpose: "Run full council review with 3 subagents."
  - name: refine
    command: "/rfc-council refine RFC-XXXX"
    purpose: "Review and iteratively improve RFC tickets."
  - name: implicit-review
    command: "/rfc-council RFC-XXXX"
    purpose: "Select mode interactively for the given RFC."

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

### Standard Review

```bash
# Review RFC-0009 tickets (single agent, all 7 gates)
/rfc-council review RFC-0009

# Output:
# - Findings bundle at evidence/rfc/RFC-0009/reviews/rfc_review_{timestamp}.yaml
# - Verdict: APPROVED | APPROVED_WITH_REMEDIATION | REJECTED
```

### Council Review

```bash
# Full council review with 3 subagents
/rfc-council review RFC-0009 --council

# This will:
# 1. Spawn 3 specialized subagents
# 2. Execute 3 review cycles
# 3. Vote on contested findings
# 4. Produce consensus verdict
```

### Refine Mode

```bash
# Review and fix issues
/rfc-council refine RFC-0009

# This will:
# 1. Run review gates
# 2. Apply remediations for MAJOR/MINOR findings
# 3. Re-run gates to verify fixes
# 4. Commit improvements
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
| refine | Same as review + modified ticket files |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (APPROVED or APPROVED_WITH_REMEDIATION) |
| 1 | Rejected (REJECTED verdict) |
| 2 | Needs human review (NEEDS_ADJUDICATION) |
| 3 | Aborted (timeout or budget exhausted) |
