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
4. **DETERMINISTIC: `GATE-PRD-CCP-MAPPING`** (Cousin Prevention Gate)
5. DETERMINISTIC: `GATE-PRD-QUALITY-COVERAGE`
6. DETERMINISTIC: `GATE-PRD-EVIDENCE-STANDARDS`
7. LLM-ASSISTED: `GATE-PRD-CONTENT` (Computed Depth)

Stop policy:

- REVIEW: stop at the first FAILED gate.
- REFINE: if a gate fails, remediate and re-run the same gate before proceeding.

### GATE-PRD-CCP-MAPPING (The Cousin Prevention Gate)

**Purpose:** Prevent cousin abstractions by enforcing CCP (Codebase Component Protocol) mapping before content review.

**Inputs:**
- PRD requirements (`requirements/REQ-*.yaml`)
- `documents/architecture/component_atlas.yaml` (the authoritative CCP)

**Pass Criteria:**
1. Every requirement MUST map to an existing CCP component, OR
2. Every unmapped requirement MUST have a `cousin_justification.yaml` artifact with:
   ```yaml
   requirement_id: REQ-XXXX
   existing_component: "path/to/component"
   capability_gap: "Specific capability that is missing"
   evidence_artifact: "EVID-XXXX"  # Test/proof showing the gap exists
   decision: "EXTEND" | "CREATE_NEW"
   decision_rationale: "Why extension is insufficient"
   ```

**Failure Mode:** If `evidence_artifact` is missing or does not demonstrate the claimed gap, emit:
- `category: TRACEABILITY_DEFECT`
- `subcategory: COUSIN_ABSTRACTION`
- `severity: BLOCKER` (not MAJOR)

**Holonic Alignment:** This gate enforces Principia Holonica Axiom IV (Economics of Attention) — "Waste is the ultimate sin."

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
- Pass 3 (clarity): remove ambiguity; **apply the Falsifiability Standard** (see below).
- Pass 4 (navigation): file placement, naming, ordering, reviewer ergonomics.

#### Falsifiability Standard (Mandatory for Pass 3)

Every acceptance criterion MUST be **machine-verifiable**. This means:

1. **Bound by a Threshold:** Replace subjective terms with numeric bounds.
   - BAD: "System MUST be fast"
   - GOOD: "p99 latency MUST be <200ms under 1000 RPS"

2. **Verifiable by Artifact:** Each criterion MUST reference an evidence artifact type.
   - BAD: "Users should find the system easy to use"
   - GOOD: "New users MUST complete onboarding in <5 minutes (EVID: session_recording_analysis)"

3. **Falsifiable by Command:** The ideal criterion can be tested by a single shell command.
   - Example: `curl -w '%{time_total}' ... | jq '.latency < 0.2'`

**Prohibited Terms (Auto-Fail):**
- "seamless", "intuitive", "user-friendly", "reliable", "robust", "performant", "scalable" (without quantification)
- "reasonable", "appropriate", "sufficient", "adequate" (without bounds)
- "should" (use MUST, SHOULD RFC 2119 style with explicit fallback)

If a criterion uses a prohibited term without quantification, emit:
- `category: EVIDENCE_DEFECT`
- `subcategory: CRITERION_VAGUE`
- `severity: BLOCKER`

### C5. Run formal review gates

Run `/prd-review review {PRD_ID}`.

## REVIEW Mode

### R1. Run gates

Use the formal rubric in `references/REVIEW_RUBRIC.md`. Stop on first FAILED gate.

### R2. Content gate = multi-angle review

For `GATE-PRD-CONTENT`, use `references/ANGLE_PROMPTS.md`.

#### Review Depth Selection (Computed, Not Self-Selected)

Depth is **computed from PRD metadata**, not chosen by the author. This prevents gaming.

**Impact Vector Computation:**

| Dimension | Low | Medium | High |
|-----------|-----|--------|------|
| `requirement_count` | ≤3 | 4-10 | >10 |
| `external_dependencies` | 0 | 1-2 | >2 |
| `net_new_abstractions` | 0 | 1 | >1 |
| `data_classification` | public | internal | pii/confidential |
| `blast_radius` | single_component | cross_component | system_wide |

**Depth Algorithm:**
```
LIGHT:    all dimensions = low
STANDARD: any dimension = medium, none = high
DEEP:     any dimension = high
```

- `requirement_count` and `external_dependencies` are **computed by GATE-PRD-SCHEMA** (not declared).
- `blast_radius` is **computed by cross-referencing** requirement locations against `component_atlas.yaml`.
- `net_new_abstractions` is **computed by GATE-PRD-CCP-MAPPING**.

**Depth Definitions:**

- **LIGHT:** Runs `VERIFIABILITY`, `TECHNICAL_FEASIBILITY`, `CUSTOMER_VALUE`.
- **STANDARD:** Runs all 8 required angles. **20% of STANDARD reviews are randomly sampled for adversarial audit** (the reviewer does not know in advance).
- **DEEP:** Runs all 10 angles + `SECURITY_POSTURE`. **Always** triggers the adversarial protocol in `references/ADVERSARIAL_REVIEW_PROMPT.md`.

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

### R2.1. Adversarial Pass (DEEP reviews + 20% STANDARD sample)

For DEEP reviews (and randomly sampled STANDARD reviews), execute the adversarial protocol from `references/ADVERSARIAL_REVIEW_PROMPT.md`.

**Adversarial Output Requirements:**

The adversarial pass MUST produce an **Adversarial Evidence Bundle** containing:

1. **Gaming Analysis:** 3 specific ways an agent could pass the acceptance criteria without truly meeting the requirement.
   ```yaml
   gaming_vectors:
     - criterion: "REQ-0001.AC-1"
       gaming_method: "Return cached stale data to meet latency target"
       countermeasure: "Add freshness bound to criterion"
   ```

2. **Cousin Search Results:** Explicit search of `component_atlas.yaml` for existing abstractions.
   ```yaml
   cousin_candidates:
     - requirement: "REQ-0003"
       existing_component: "core/cache.rs::LruCache"
       overlap_percentage: 80
       recommendation: "EXTEND" | "REUSE" | "JUSTIFIED_NEW"
   ```

3. **Zero-Sum Tradeoff Declaration:** For each major design decision, the **specific metric degraded**.
   ```yaml
   tradeoffs:
     - decision: "Use eventual consistency"
       benefit: "Lower latency (p99 < 50ms)"
       cost: "Stale reads up to 5 seconds"
       acceptable: true
       rationale: "User-facing reads tolerate staleness per customer interviews"
   ```

4. **Meta-Improvement Proposal:** One specific update to `ANGLE_PROMPTS.md` or `SKILL.md` derived from this review.

**Failure Mode:** If adversarial pass finds a BLOCKER-severity gaming vector with no countermeasure, the PRD verdict is `NEEDS_REMEDIATION` regardless of other gate statuses.

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
   - **Run Delta-Quality Check** before re-running gate (see below).
   - Re-run the same gate until it passes or the remaining issues require adjudication.
3. Continue to the next gate.

Hard rule: do not "paper over" deficits with prose. Prefer improving the underlying requirements/evidence chain.

### Delta-Quality Check (Anti-Papering Mechanism)

Before re-running a gate after remediation, verify the fix is **substantive**:

**Substance Test:**
1. If the fix only adds prose (comments, rationale, notes) without changing:
   - A quantitative bound
   - An evidence artifact reference
   - A CCP mapping
   - An acceptance criterion's test command

   Then the fix is `PROSE_ONLY` and MUST be flagged:
   ```yaml
   delta_quality:
     finding_id: FND-PRD-XXXX-001
     fix_type: "PROSE_ONLY"
     verdict: "INSUFFICIENT"
     guidance: "Fix adds explanation but does not address the structural defect"
   ```

2. If `PROSE_ONLY` fix is attempted 2+ times for the same finding, escalate to `NEEDS_ADJUDICATION`.

**Valid Fix Types:**
- `BOUND_ADDED`: Added quantitative threshold
- `EVIDENCE_LINKED`: Added evidence artifact reference
- `CCP_MAPPED`: Added component mapping
- `CRITERION_REWRITTEN`: Rewrote criterion to be falsifiable
- `REQUIREMENT_REMOVED`: Removed the problematic requirement (valid if scope adjustment is justified)

This prevents the recursive "fix loop" where an LLM adds bureaucratic filler to satisfy the letter of a finding without addressing its spirit.

## Verdict Rules

- PASSED: all gates passed
- FAILED: any gate failed with BLOCKER findings
- NEEDS_REMEDIATION: only MAJOR/MINOR findings remain
- NEEDS_ADJUDICATION: a required decision is missing or the LLM-assisted gate is uncertain

## Variance-Triggered Feedback Loop

PRD review does not end at gate passage. Implementation can diverge from specification.

### GATE-PRD-RECONCILIATION (Post-Merge)

**Trigger:** After any PR referencing `PRD-XXXX` is merged to main.

**Inputs:**
- PRD requirements and CCP mapping
- Merged PR diff (new symbols, files, dependencies)

**Reconciliation Check:**
1. Extract all new public symbols (functions, structs, traits, types) from the diff.
2. For each new symbol, verify it maps to the PRD's CCP projection.
3. If a symbol introduces a net-new abstraction not in the PRD:
   - Emit `VARIANCE_EVENT`:
     ```yaml
     variance_id: VAR-{PRD_ID}-{NNN}
     pr_ref: "PR#123"
     symbol: "crate::new_retry::CustomRetry"
     expected_mapping: "core/retry.rs::RetryPolicy"
     variance_type: "UNDOCUMENTED_ABSTRACTION"
     ```

**Feedback Actions:**
1. Auto-create ticket: `"PRD-XXXX Variance: Reconcile {symbol} with specification"`
2. Add variance pattern to `references/COUNTERMEASURE_PATTERNS.md`
3. If variance pattern recurs 3+ times for same `subcategory`, escalate to SKILL.md amendment proposal

**Holonic Alignment:** This closes the loop per Principia Holonica Axiom II (Topology of Truth) — "If you cannot prove it via a signed entry in the Ledger, it did not happen."

### Signal-to-Noise Ratio Check

After every review, compute:

```
SNR = (BLOCKER + MAJOR findings) / (total findings)
```

- If SNR < 0.5 (more than half are MINOR/INFO), the review depth was **miscalibrated**.
- Emit `REVIEW_CALIBRATION_WARNING` and record for depth algorithm tuning.

This prevents "Alert Fatigue" — the Pragmatist's concern.

## References

- `references/REVIEW_RUBRIC.md`: gate definitions + deterministic verification steps
- `references/FINDING_CATEGORIES.md`: finding taxonomy + FindingSignature definition
- `references/ANGLE_PROMPTS.md`: multi-angle content review prompts
- `references/FEEDBACK_LOOPS.md`: how downstream signals feed PRD improvement
- `references/COUNTERMEASURE_PATTERNS.md`: recurrence → countermeasure patterns
- `references/CREATE_PRD_PROMPT.md`: end-to-end drafting guidance
- `references/ADVERSARIAL_REVIEW_PROMPT.md`: adversarial meta-review protocol
- `documents/architecture/component_atlas.yaml`: authoritative CCP for cousin prevention
- `documents/skills/holonic-agent-network/references/principia-holonic.md`: axiomatic foundation (Existence, Truth, Economy)

## Gemini Meta-Review (How to get Gemini to improve PRDs and this skill)

Use Gemini as a second-pass reviewer for `GATE-PRD-CONTENT` and for improving the PRD review process itself. For `DEEP` reviews, use the protocol in `references/ADVERSARIAL_REVIEW_PROMPT.md`.

When prompting Gemini:

1. Provide the minimum required context pack:
   - The PRD directory contents (`documents/prds/{PRD_ID}/`)
   - `documents/standards/lint/LINT_SPEC.yaml`
   - `references/REVIEW_RUBRIC.md`, `references/ANGLE_PROMPTS.md`, `references/FINDING_CATEGORIES.md`, `references/ADVERSARIAL_REVIEW_PROMPT.md`
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
