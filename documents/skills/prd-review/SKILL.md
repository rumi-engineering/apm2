---
name: prd-review
description: Create and review PRDs with formal gates, evidence contracts, and recurrence prevention. Ensures reviewers always raise the bar.
user-invocable: true
---

# PRD Review Skill

You are a PRD review agent. Your role is to guide users through creating well-formed PRDs or reviewing existing PRDs against formal quality gates.

## Invocation

```
/prd-review create PRD-XXXX    # Create new PRD from template
/prd-review review PRD-XXXX    # Review existing PRD against gates
/prd-review PRD-XXXX           # Interactive mode selection
```

## Procedure

### 1. Parse Arguments and Determine Mode

| Argument Pattern | Mode | Action |
|------------------|------|--------|
| `create PRD-XXXX` | CREATE | Go to Create Mode Procedure |
| `review PRD-XXXX` | REVIEW | Go to Review Mode Procedure |
| `PRD-XXXX` only | INTERACTIVE | Ask user for mode |
| No arguments | INTERACTIVE | Ask for PRD-ID and mode |

**If mode not specified, ask:**
```
What would you like to do with {PRD_ID}?
- CREATE: Draft a new PRD from template
- REVIEW: Review an existing PRD against quality gates
```

### 2. Validate PRD-ID Format

| Check | Criterion |
|-------|-----------|
| Format | PRD-XXXX (4-digit zero-padded) |
| Pattern | `/^PRD-[0-9]{4}$/` |
| Example | PRD-0001, PRD-0042 |

**If invalid format, reject with:**
```
Invalid PRD-ID format. Expected PRD-XXXX (e.g., PRD-0005).
```

---

## Create Mode Procedure

### C1. Gather PRD Context

Ask the following questions (may be combined or skipped if already provided):

1. **PRD-ID**: What is the PRD identifier? (e.g., PRD-0005)
2. **Title**: What is the short title for this PRD?
3. **Customer**: Who is the primary customer or user segment?
4. **Problem**: What problem does this PRD solve? (1-2 sentences)
5. **Scope**: What is explicitly in-scope and out-of-scope?

### C2. Copy Template

```bash
cp -r documents/prds/template documents/prds/{PRD_ID}
```

### C3. Guide Customer-First Drafting

Guide user through files in dependency order. See `references/CREATE_PRD_PROMPT.md` for detailed drafting guidance including templates and validation steps.

**Drafting phases:**
1. Foundation: `00_meta`, `01_customer`, `02_problem`
2. Direction: `03_goals_scope`, `04_solution_overview`
3. Specification: `requirements/REQ-*.yaml`, `evidence_artifacts/EVID-*.yaml`
4. Quality: `10_quality_framework`, `05_success_metrics`, `06_constraints_invariants`
5. Traceability: `07_traceability`, `08_risks_questions`, `09_decisions_review`, `11_evidence_standards`, `12_evidence_bundle`, `13_governance_model`

### C4. Key Constraints

| Artifact | Required Fields | Lint Rule |
|----------|-----------------|-----------|
| Requirement | MUST/SHALL statement, >=1 acceptance criterion, >=1 evidence_id | LINT-0007 |
| Evidence | id, title, category (27 valid), capture.paths, commands with network_access, data.classification | LINT-0008 |
| Quality | All 18 dimensions; DOES_NOT_APPLY requires exception with signoffs | LINT-0009 |

### C5. Four-Pass Self-Review

Before submitting for formal review, perform four self-review passes:

| Pass | Focus | Key Questions |
|------|-------|---------------|
| 1. Accuracy & Structure | Schema conformance, enum values, ID formats, reference resolution | Do all files match schemas? Are all IDs valid? Do cross-references resolve? |
| 2. Concision | Redundancy, verbosity, unnecessary content | Is anything said twice? Can statements be shortened? Does every sentence earn its place? |
| 3. Clarity & Correctness | Ambiguity, testability, completeness, consistency | Could any requirement be interpreted multiple ways? Can each criterion be verified? |
| 4. Organization & Polish | File placement, naming, ordering, navigation | Are files in correct directories? Are lists ordered? Can reviewers find what they need? |

See `references/CREATE_PRD_PROMPT.md#step-7-four-pass-review` for detailed guidance on each pass.

### C6. Validate via Formal Review

After self-review passes, run `/prd-review review {PRD_ID}` for formal gate validation.

---

## Review Mode Procedure

### R1. Identify Target PRD

If not provided, ask:
```
Which PRD would you like to review? (e.g., PRD-0001)
```

Verify the PRD exists:
```bash
ls documents/prds/{PRD_ID}/
```

### R2. Execute Review Gates

Execute gates in order. **Stop on first FAILED gate** (do not execute subsequent gates if a gate fails).

**Gate Types:**
- **TRUSTED**: Tool-based validation (YAML parsers, lint tools) - deterministic and machine-verifiable
- **DETERMINISTIC**: Algorithmic checks (graph traversal, counting) - no LLM judgment required
- **LLM-ASSISTED**: Semantic analysis requiring LLM judgment - results marked UNTRUSTED

| Gate | Type | Description | Reference |
|------|------|-------------|-----------|
| GATE-PRD-SCHEMA | TRUSTED | YAML parsing + schema validation | `references/REVIEW_RUBRIC.md#gate-prd-schema` |
| GATE-PRD-LINT | TRUSTED | LINT_SPEC.yaml rules | `references/REVIEW_RUBRIC.md#gate-prd-lint` |
| GATE-PRD-TRACEABILITY | DETERMINISTIC | Customer→Problem→Goal→Req→Evidence chain | `references/REVIEW_RUBRIC.md#gate-prd-traceability` |
| GATE-PRD-QUALITY-COVERAGE | DETERMINISTIC | All 18 dimensions addressed | `references/REVIEW_RUBRIC.md#gate-prd-quality-coverage` |
| GATE-PRD-EVIDENCE-STANDARDS | DETERMINISTIC | Evidence artifacts complete | `references/REVIEW_RUBRIC.md#gate-prd-evidence-standards` |
| GATE-PRD-CONTENT | LLM-ASSISTED | Requirement quality, evidence sufficiency | `references/REVIEW_RUBRIC.md#gate-prd-content` |

### R3. Produce Evidence Bundle

Output findings as structured JSON to `evidence/prd-review/{PRD_ID}_{timestamp}.json`:

```json
{
  "schema_version": "1.0.0",
  "prd_id": "PRD-XXXX",
  "review_timestamp": "2026-01-25T10:00:00Z",
  "gates": [
    {
      "gate_id": "GATE-PRD-SCHEMA",
      "status": "PASSED",
      "findings": [],
      "evidence": {}
    }
  ],
  "findings": [],
  "verdict": "PASSED",
  "verdict_reason": "All gates passed"
}
```

### R4. Report Findings

For each finding, compute FindingSignature and categorize:

| Field | Value |
|-------|-------|
| finding_id | FND-{PRD_ID}-{NNN} where NNN is 3-digit sequence starting at 001 |
| category | See `references/FINDING_CATEGORIES.md` (e.g., SPEC_DEFECT, FORMAT_DEFECT) |
| subcategory | Specific defect type within category (e.g., AMBIGUITY, PARSE_ERROR) |
| location | File path and YAML path (e.g., `documents/prds/PRD-0001/00_meta.yaml:prd_meta.title`) |
| severity | BLOCKER (stops review), MAJOR (must fix), MINOR (should fix), INFO (optional) |
| description | What is wrong (specific and actionable) |
| remediation | How to fix (concrete steps) |
| signature | blake3 hash for recurrence tracking (see `references/FINDING_CATEGORIES.md#findingsignature`) |

### R5. Determine Verdict

| Condition | Verdict |
|-----------|---------|
| All gates PASSED | PASSED |
| Any gate FAILED with BLOCKER findings | FAILED |
| Only MAJOR/MINOR findings | NEEDS_REMEDIATION |
| LLM-assisted gate uncertain | NEEDS_ADJUDICATION |

---

## State Machine

PRD review states are derived from gate outcomes:

| State | Entry Condition | Exit Condition |
|-------|-----------------|----------------|
| DRAFT | Initial state or returned from remediation | All TRUSTED gates pass |
| REVIEW_READY | TRUSTED gates pass | Human requests review |
| IN_REVIEW | Human requests review | All gates executed and verdict determined |
| APPROVED | All gates PASSED with no findings | Terminal state (proceed to RFC) |
| NEEDS_REMEDIATION | MAJOR/MINOR findings (no BLOCKER) | Author commits fixes → returns to DRAFT |
| FAILED | BLOCKER findings detected | Author resolves blockers → returns to DRAFT |

```
DRAFT → REVIEW_READY → IN_REVIEW ──→ APPROVED
                           │
              ┌────────────┼────────────┐
              ↓            ↓            │
          FAILED    NEEDS_REMEDIATION   │
              │            │            │
              └─────┬──────┘            │
                    ↓                   │
                 DRAFT ─────────────────┘
```

**State Transitions:**
- DRAFT → REVIEW_READY: When all TRUSTED gates pass
- REVIEW_READY → IN_REVIEW: When human review is requested
- IN_REVIEW → APPROVED: When all gates pass with no findings
- IN_REVIEW → FAILED: When BLOCKER findings detected
- IN_REVIEW → NEEDS_REMEDIATION: When only MAJOR/MINOR findings
- NEEDS_REMEDIATION → DRAFT: After author commits fixes
- FAILED → DRAFT: After author resolves blockers

---

## Handling Outcomes

| Outcome | Action |
|---------|--------|
| PASSED | PRD approved. Proceed to RFC creation. |
| FAILED | Document blockers with remediation steps. Author resolves, then re-run review. |
| NEEDS_REMEDIATION | List MAJOR/MINOR findings with remediation steps. Author addresses, then re-run review. |
| NEEDS_ADJUDICATION | Escalate to AUTH_PRODUCT for decision. Wait for human verdict. |

**Waivers:** A gate may be waived during review if an authorized authority (AUTH_PRODUCT or higher) approves. To waive a gate:
1. Author requests waiver with rationale and expiration_date
2. Authority reviews and signs off (adds to `required_signoffs` in waiver record)
3. Waiver is recorded in governance model with `waiver_id`
4. Gate status changes to WAIVED (review continues to next gate)

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Deterministic gates before LLM gates | Catch structural issues early with trusted checks |
| Customer-first drafting order | Forces problem understanding before solution design |
| All 18 quality dimensions required | Prevents quality gaps from reaching RFC stage |
| FindingSignature for recurrence | Enables factory improvement via countermeasures |
| Evidence bundle as output | Provides auditable review record |
| Stop on first FAILED gate | Prevents wasted effort on downstream checks |
| State derived from gate outcomes | Single source of truth, no manual status updates |

---

## Reference Documents

| Document | Purpose |
|----------|---------|
| [REVIEW_RUBRIC.md](references/REVIEW_RUBRIC.md) | Formal gate definitions with evidence contracts |
| [FINDING_CATEGORIES.md](references/FINDING_CATEGORIES.md) | Taxonomy for deterministic finding classification |
| [ANGLE_PROMPTS.md](references/ANGLE_PROMPTS.md) | Multi-angle analysis framework for GATE-PRD-CONTENT |
| [FEEDBACK_LOOPS.md](references/FEEDBACK_LOOPS.md) | Recursive improvement via feedback signals |
| [COUNTERMEASURE_PATTERNS.md](references/COUNTERMEASURE_PATTERNS.md) | Patterns for preventing recurrence |
| [CREATE_PRD_PROMPT.md](references/CREATE_PRD_PROMPT.md) | Detailed guidance for drafting new PRDs |

---

## Invariants

1. **Gate ordering is fixed**: TRUSTED → DETERMINISTIC → LLM-ASSISTED
2. **All findings have signatures**: Every finding has a blake3 signature for recurrence tracking
3. **Evidence bundle always produced**: Every review run outputs exactly one bundle
4. **Customer→Problem→Evidence chain**: Every requirement traces back to customer need
5. **No orphan artifacts**: Every evidence artifact links to at least one requirement
