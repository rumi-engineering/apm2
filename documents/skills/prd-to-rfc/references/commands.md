# PRD to RFC Commands

commands[4]:
  - name: default
    command: "/prd-to-rfc PRD-XXXX"
    purpose: "Run full PRD-to-RFC pipeline with default settings."
  - name: limited-iterations
    command: "/prd-to-rfc PRD-XXXX --max-iterations 3"
    purpose: "Limit review loop to 3 iterations before escalation."
  - name: force-council
    command: "/prd-to-rfc PRD-XXXX --council"
    purpose: "Force council mode for all review iterations."
  - name: dry-run
    command: "/prd-to-rfc PRD-XXXX --dry-run"
    purpose: "Show what would be done without making changes."

---

## Usage Examples

### Basic Usage

```bash
# Compile PRD-0005 into an approved RFC
/prd-to-rfc PRD-0005

# This will:
# 1. Validate PRD-0005 exists with CCP
# 2. Run /rfc-council create PRD-0005 to generate RFC
# 3. Run /rfc-council review RFC-XXXX until APPROVED (up to 5 iterations)
# 4. Emit orchestration evidence bundle
```

### Resuming Existing Work

```bash
# If RFC already exists for the PRD, orchestrator skips create phase
/prd-to-rfc PRD-0005

# This will:
# 1. Detect existing RFC-0010 linked to PRD-0005
# 2. Skip create phase
# 3. Continue review iterations from where it left off
```

### Limited Iterations

```bash
# Limit to 3 review iterations
/prd-to-rfc PRD-0005 --max-iterations 3

# This will escalate after 3 REJECTED verdicts instead of default 5
```

### Council Mode

```bash
# Force council mode for thorough multi-agent review
/prd-to-rfc PRD-0005 --council

# This will run /rfc-council review RFC-XXXX --council for each iteration
```

### Dry Run

```bash
# Preview what would happen without making changes
/prd-to-rfc PRD-0005 --dry-run

# This will:
# 1. Validate inputs
# 2. Log what would be done
# 3. NOT invoke rfc-council
# 4. NOT create evidence files
# 5. NOT commit anything
```

---

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `PRD-XXXX` | PRD identifier (required) | - |
| `--max-iterations N` | Maximum review iterations before escalation | 5 |
| `--council` | Force council mode for reviews | false |
| `--dry-run` | Preview mode, no changes | false |

---

## Output Files

| Phase | Output Path |
|-------|-------------|
| Create | `documents/rfcs/RFC-XXXX/`, `documents/work/tickets/TCK-*.yaml` |
| Review | `evidence/rfc/RFC-XXXX/reviews/rfc_review_{timestamp}.yaml` |
| Final | `evidence/prd/{PRD_ID}/orchestration/prd_to_rfc_complete_{timestamp}.yaml` |

---

## Terminal Verdicts

| Verdict | Status | Description |
|---------|--------|-------------|
| APPROVED | Success | RFC passed all gates and achieved consensus. |
| APPROVED_WITH_REMEDIATION | Success | RFC passed with minor findings already remediated. |
| REJECTED | Terminal | Hit MAX_ITERATIONS without achieving approval. |
| NEEDS_ADJUDICATION | Escalated | Council deadlocked or STALL detected in review loop. |
| FAILED | Error | Orchestration aborted due to missing prerequisites (PRD/CCP). |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (APPROVED or APPROVED_WITH_REMEDIATION) |
| 1 | Escalated (NEEDS_ADJUDICATION or REJECTED) |
| 2 | Error (FAILED) |
| 3 | Aborted (Timeout or budget exhausted) |

---

## Progress Tracking

The orchestrator logs progress at each phase:

```
[prd-to-rfc] Validating PRD-0005...
[prd-to-rfc] CCP found at evidence/prd/PRD-0005/ccp/
[prd-to-rfc] No existing RFC found, running create phase...
[prd-to-rfc] Invoking /rfc-council create PRD-0005
[prd-to-rfc] RFC-0010 created with 8 tickets
[prd-to-rfc] Starting review iteration 1 of 5...
[prd-to-rfc] Iteration 1 verdict: REJECTED (3 MAJOR findings)
[prd-to-rfc] Starting review iteration 2 of 5...
[prd-to-rfc] Iteration 2 verdict: REJECTED (1 MAJOR finding)
[prd-to-rfc] Starting review iteration 3 of 5...
[prd-to-rfc] Iteration 3 verdict: APPROVED
[prd-to-rfc] Orchestration complete: PRD-0005 -> RFC-0010 (APPROVED)
```

---

## Troubleshooting

### PRD_NOT_FOUND

```
Error: PRD_NOT_FOUND: No PRD found at documents/prds/PRD-0005/
```

**Solution**: Ensure PRD exists. Create with `/prd-review PRD-0005` if needed.

### CCP_REQUIRED

```
Error: CCP_REQUIRED: No CCP found at evidence/prd/PRD-0005/ccp/
```

**Solution**: Generate CCP first with `/idea-compiler PRD-0005`.

### MAX_ITERATIONS_EXCEEDED

```
Escalated: MAX_ITERATIONS_EXCEEDED: 5 review iterations without APPROVED
```

**Solution**: Review verdict history in evidence bundle. Consider:
- Manually reviewing tickets for systemic issues
- Running `/rfc-council review RFC-XXXX --council` for deeper analysis
- Adjusting PRD scope if consistently failing

### NEEDS_ADJUDICATION

```
Escalated: RFC requires human adjudication
```

**Solution**: Review the contested findings in the evidence bundle. The council
was unable to reach consensus. Human judgment is required to resolve.
