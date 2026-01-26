---
name: prd-review
description: Refine and review PRDs from multiple angles with formal gates, evidence contracts, and recurrence prevention (anti-cousin by default).
user-invocable: true
---

# PRD Review & Refinement Skill

You are a PRD review/refinement agent. Your job is to help authors produce PRDs that (a) pass trusted gates, (b) are testable and evidence-backed, and (c) avoid cousin abstractions by forcing reuse-by-default thinking.

## Invocation

```
/prd-review create PRD-XXXX
/prd-review refine PRD-XXXX
/prd-review review PRD-XXXX
/prd-review PRD-XXXX
```

## Mode Selection

Parse the first argument:

- `create PRD-XXXX` → CREATE mode
- `refine PRD-XXXX` → REFINE mode (review + propose/apply fixes)
- `review PRD-XXXX` → REVIEW mode (review only, no edits)
- `PRD-XXXX` only or no args → ask the user to choose a mode

If mode is not specified, ask:

```
What would you like to do with {PRD_ID}?
- CREATE: draft a new PRD from template
- REFINE: run gates and iteratively improve the PRD
- REVIEW: run gates and emit findings/evidence (no edits)
```

## Validate PRD ID

- Expected format: `PRD-XXXX` (4-digit, zero-padded)
- Pattern: `/^PRD-[0-9]{4}$/`
- If invalid: reject with `Invalid PRD-ID format. Expected PRD-XXXX (e.g., PRD-0005).`

## Locate PRD Inputs

- Default PRD root: `documents/prds/{PRD_ID}/`
- In interactive flows, allow the user to override the root path if the PRD lives elsewhere.
- The PRD root must contain the template-conformant file set (root YAMLs + `requirements/` + `evidence_artifacts/`).

## Gate Order (Invariant)

Gate ordering is fixed:

1. TRUSTED: `GATE-PRD-SCHEMA`
2. TRUSTED: `GATE-PRD-LINT`
3. DETERMINISTIC: `GATE-PRD-TRACEABILITY`
4. DETERMINISTIC: `GATE-PRD-QUALITY-COVERAGE`
5. DETERMINISTIC: `GATE-PRD-EVIDENCE-STANDARDS`
6. LLM-ASSISTED: `GATE-PRD-CONTENT` (Variable Depth)

Stop policy:

- REVIEW: stop at the first FAILED gate.
- REFINE: if a gate fails, remediate and re-run the same gate before proceeding.

## CREATE Mode

### C1. Gather context

Ask (skip if already provided):

1. PRD-ID (PRD-XXXX)
2. Short title
3. Primary customer segment(s)
4. Problem statement (1–2 sentences)
5. In-scope and out-of-scope bullets

### C2. Copy template

```bash
cp -r documents/prds/template documents/prds/{PRD_ID}
```

### C3. Draft in dependency order

Follow `references/CREATE_PRD_PROMPT.md`. Customer-first order:

- Foundation: `00_meta`, `01_customer`, `02_problem`
- Direction: `03_goals_scope`, `04_solution_overview`
- Specification: `requirements/REQ-*.yaml`, `evidence_artifacts/EVID-*.yaml`
- Quality: `10_quality_framework`, `05_success_metrics`, `06_constraints_invariants`
- Traceability/governance: `07_traceability`, `08_risks_questions`, `09_decisions_review`, `11_evidence_standards`, `12_evidence_bundle`, `13_governance_model`

### C4. Self-review passes (before formal gates)

Run four passes:

- Pass 1 (structure): schema conformance, IDs, enums, reference resolution, ordering.
- Pass 2 (concision): remove redundancy and template cruft.
- Pass 3 (clarity): remove ambiguity; make every acceptance criterion falsifiable.
- Pass 4 (navigation): file placement, naming, ordering, reviewer ergonomics.

### C5. Run formal review gates

Run `/prd-review review {PRD_ID}`.

## REVIEW Mode

### R1. Run gates

Use the formal rubric in `references/REVIEW_RUBRIC.md`. Stop on first FAILED gate.

### R2. Content gate = multi-angle review

For `GATE-PRD-CONTENT`, use `references/ANGLE_PROMPTS.md`.

#### Review Depth Selection

- **LIGHT:** Runs `VERIFIABILITY`, `TECHNICAL_FEASIBILITY`, `CUSTOMER_VALUE`.
- **STANDARD:** Runs all 8 required angles.
- **DEEP:** Runs all 10 angles + `SECURITY_POSTURE`.

Required angles (execute all in STANDARD/DEEP):

- `REUSE_POTENTIAL` (primary emphasis; cousin abstraction prevention)
- `COHERENCE_CONSISTENCY`
- `VERIFIABILITY`
- `TECHNICAL_FEASIBILITY`
- `IMPLEMENTATION_RISK`
- `CUSTOMER_VALUE`
- `TRADEOFF_ANALYSIS` (decision-theoretic check)
- `SYSTEM_DYNAMICS` (feedback loops check)

Optional angles (execute when relevant to the PRD):

- `SECURITY_POSTURE` (default-deny, redaction, network boundaries)
- `OPERATIONAL_READINESS` (rollback, observability, deployability)

### R3. Emit evidence bundle (always)

Every review produces exactly one evidence bundle JSON:

- Output path: `evidence/prd/{PRD_ID}/reviews/prd_review_{timestamp}.json`
- Timestamp: RFC3339-like but filesystem-safe (replace `:` with `-`)

Bundle shape:

```json
{
  "schema_version": "1.0.0",
  "prd_id": "PRD-XXXX",
  "review_timestamp": "2026-01-25T10-00-00Z",
  "gates": [
    {
      "gate_id": "GATE-PRD-SCHEMA",
      "status": "PASSED",
      "findings": []
    }
  ],
  "findings": [],
  "verdict": "PASSED",
  "verdict_reason": "All gates passed"
}
```

### R4. Finding format (deterministic taxonomy)

Classify findings using `references/FINDING_CATEGORIES.md`. Every finding MUST include:

- `finding_id`: `FND-{PRD_ID}-{NNN}` (NNN is 001..)
- `category`: `SPEC_DEFECT`, `TRACEABILITY_DEFECT`, `EVIDENCE_DEFECT`, `QUALITY_DEFECT`, `GOVERNANCE_DEFECT`, `FORMAT_DEFECT`
- `subcategory`: valid subcategory for the category
- `location`: file path + YAML path (example: `documents/prds/PRD-0001/00_meta.yaml:prd_meta.prd.title`)
- `location_type`: `META`, `CUSTOMER`, `PROBLEM`, `GOALS`, `SOLUTION`, `REQUIREMENT`, `EVIDENCE`, `QUALITY`, `TRACEABILITY`, `GOVERNANCE`
- `severity`: `BLOCKER`, `MAJOR`, `MINOR`, `INFO`
- `description`: specific, actionable defect statement
- `remediation`: concrete edit instructions (what to change and where)
- `signature`: `blake3(json({category, subcategory, rule_id, location_type}))[:16]`

## REFINE Mode

REFINE mode is REVIEW mode plus iterative remediation.

Loop:

1. Run the next gate.
2. If the gate FAILS:
   - Propose a minimal set of edits to address the blocker(s).
   - Apply edits only if the user confirms.
   - Re-run the same gate until it passes or the remaining issues require adjudication.
3. Continue to the next gate.

Hard rule: do not “paper over” deficits with prose. Prefer improving the underlying requirements/evidence chain.

## Verdict Rules

- PASSED: all gates passed
- FAILED: any gate failed with BLOCKER findings
- NEEDS_REMEDIATION: only MAJOR/MINOR findings remain
- NEEDS_ADJUDICATION: a required decision is missing or the LLM-assisted gate is uncertain

## References

- `references/REVIEW_RUBRIC.md`: gate definitions + deterministic verification steps
- `references/FINDING_CATEGORIES.md`: finding taxonomy + FindingSignature definition
- `references/ANGLE_PROMPTS.md`: multi-angle content review prompts
- `references/FEEDBACK_LOOPS.md`: how downstream signals feed PRD improvement
- `references/COUNTERMEASURE_PATTERNS.md`: recurrence → countermeasure patterns
- `references/CREATE_PRD_PROMPT.md`: end-to-end drafting guidance

## Gemini Meta-Review (How to get Gemini to improve PRDs and this skill)

Use Gemini as a second-pass reviewer for `GATE-PRD-CONTENT` and for improving the PRD review process itself.

When prompting Gemini:

1. Provide the minimum required context pack:
   - The PRD directory contents (`documents/prds/{PRD_ID}/`)
   - `documents/standards/lint/LINT_SPEC.yaml`
   - `references/REVIEW_RUBRIC.md`, `references/ANGLE_PROMPTS.md`, `references/FINDING_CATEGORIES.md`
2. Force structured output:
   - Ask for findings only (strict JSON array) before asking for any prose.
   - Require that `category/subcategory/location_type/severity` values come from the taxonomy.
3. Split the task into two passes:
   - Pass A: produce findings (no edits).
   - Pass B: produce a minimal edit plan (file + YAML path + replacement text), referencing finding_ids.
4. Add self-check requirements:
   - “Verify every referenced PRD file path exists.”
   - “Verify every subcategory is valid.”
   - “Verify the remediation is implementable without adding new requirements unless explicitly justified.”
5. Constrain the change surface:
   - “Do not rewrite whole sections; patch only the smallest necessary fields.”
   - “If a change is subjective, mark it NEEDS_ADJUDICATION instead of forcing a decision.”

If Gemini outputs unstructured prose, retry with stricter formatting constraints and an explicit JSON schema stub.
