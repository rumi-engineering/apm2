# Finding Categories

Taxonomy for deterministic finding classification. Enables FindingSignature computation, recurrence tracking, and automated countermeasure recommendations.

---

## SPEC_DEFECT

| Subcategory | Description |
|-------------|-------------|
| AMBIGUITY | Requirement can be interpreted multiple ways |
| INCOMPLETENESS | Requirement missing necessary detail |
| INCONSISTENCY | Requirement contradicts another |
| UNTESTABLE | Cannot write pass/fail test |
| UNDERSPECIFIED | Lacks measurable criteria |

---

## TRACEABILITY_DEFECT

| Subcategory | Description |
|-------------|-------------|
| ORPHAN_REQ | Requirement not linked to customer need |
| ORPHAN_EVID | Evidence not referenced by any requirement |
| MISSING_CHAIN | Gap in Customer→Problem→Goal→REQ→EVID |
| CIRCULAR_REF | Circular dependency in references |
| BROKEN_REF | Reference to non-existent artifact |

---

## EVIDENCE_DEFECT

| Subcategory | Description |
|-------------|-------------|
| INSUFFICIENT | Evidence doesn't adequately demonstrate requirement |
| NON_REPRODUCIBLE | Evidence cannot be independently reproduced |
| MISSING_CAPTURE | No capture.paths specified |
| NETWORK_UNDEFINED | Command doesn't declare network_access |
| STALE_EVIDENCE | Evidence older than requirement modification |
| INVALID_NETWORK_ACCESS | network_access not valid enum value |
| MISSING_DATA_CLASS | Missing data.classification or data.redaction |

---

## QUALITY_DEFECT

| Subcategory | Description |
|-------------|-------------|
| UNCOVERED | Quality dimension not addressed (missing from framework) |
| INVALID_EXCEPTION | DOES_NOT_APPLY without proper exception (missing `exception.requested: true`, `exception.rationale`, or `exception.required_signoffs`) |
| MISSING_GUARDRAILS | Dimension with `disposition: DELEGATED_WITH_GUARDRAILS` but empty `delegation.guardrails` array |
| WEAK_EVIDENCE | Evidence category in `delegation.required_evidence_categories` not linked to actual evidence |
| MISSING_SIGNOFFS | Exception missing `required_signoffs` list (must have at least one authority) |

---

## GOVERNANCE_DEFECT

| Subcategory | Description |
|-------------|-------------|
| MISSING_GATE | Required gate not present in review |
| INVALID_AUTHORITY | Signoff from unauthorized authority |
| WAIVER_EXPIRED | Waiver past expiration_date |
| WAIVER_MISSING | WAIVED status but no waiver_id |
| SCOPE_MISMATCH | Waiver scope doesn't cover gate |

---

## FORMAT_DEFECT

| Subcategory | Description |
|-------------|-------------|
| PARSE_ERROR | YAML fails to parse |
| SCHEMA_VIOLATION | Document doesn't match schema |
| ID_FORMAT | ID doesn't match canonical pattern |
| SORT_ORDER | Lists not lexicographically sorted |
| DUPLICATE_ID | Same ID used twice |
| TAB_CHARACTER | File contains tab characters |

---

## FindingSignature

Deterministic signature for recurrence tracking. Computed as `blake3(json({category, subcategory, rule_id, location_type}))[:16]`.

**Fields:**
- `category`: One of the six categories above (e.g., SPEC_DEFECT)
- `subcategory`: Specific defect type within category (e.g., AMBIGUITY)
- `rule_id`: The lint rule or gate check that detected it (e.g., LINT-0007, or empty if no rule)
- `location_type`: The type of file where finding occurred: `META`, `CUSTOMER`, `PROBLEM`, `GOALS`, `SOLUTION`, `REQUIREMENT`, `EVIDENCE`, `QUALITY`, `TRACEABILITY`, or `GOVERNANCE`

**Properties:** Deterministic, content-based (not instance-based), stable across location changes within same location_type.

---

## Recurrence Thresholds

| Occurrences | Action |
|-------------|--------|
| 3 | Flag for countermeasure consideration |
| 5 | Auto-create countermeasure work item |
| 10 | Escalate to AUTH_PRODUCT |

---

## Severity Assignment Rules

Severity is determined by category and subcategory combination.

| Category | Subcategory | Default Severity |
|----------|-------------|------------------|
| SPEC_DEFECT | AMBIGUITY | MAJOR |
| SPEC_DEFECT | INCOMPLETENESS | MAJOR |
| SPEC_DEFECT | INCONSISTENCY | BLOCKER |
| SPEC_DEFECT | UNTESTABLE | MAJOR |
| SPEC_DEFECT | UNDERSPECIFIED | MAJOR |
| TRACEABILITY_DEFECT | ORPHAN_REQ | MAJOR |
| TRACEABILITY_DEFECT | ORPHAN_EVID | MINOR |
| TRACEABILITY_DEFECT | MISSING_CHAIN | BLOCKER |
| TRACEABILITY_DEFECT | CIRCULAR_REF | BLOCKER |
| TRACEABILITY_DEFECT | BROKEN_REF | BLOCKER |
| EVIDENCE_DEFECT | INSUFFICIENT | MAJOR |
| EVIDENCE_DEFECT | NON_REPRODUCIBLE | MAJOR |
| EVIDENCE_DEFECT | MISSING_CAPTURE | MAJOR |
| EVIDENCE_DEFECT | NETWORK_UNDEFINED | MAJOR |
| EVIDENCE_DEFECT | INVALID_NETWORK_ACCESS | MAJOR |
| EVIDENCE_DEFECT | MISSING_DATA_CLASS | MAJOR |
| EVIDENCE_DEFECT | STALE_EVIDENCE | MINOR |
| QUALITY_DEFECT | UNCOVERED | BLOCKER |
| QUALITY_DEFECT | INVALID_EXCEPTION | BLOCKER |
| QUALITY_DEFECT | MISSING_GUARDRAILS | MAJOR |
| QUALITY_DEFECT | WEAK_EVIDENCE | MINOR |
| QUALITY_DEFECT | MISSING_SIGNOFFS | BLOCKER |
| GOVERNANCE_DEFECT | MISSING_GATE | BLOCKER |
| GOVERNANCE_DEFECT | INVALID_AUTHORITY | BLOCKER |
| GOVERNANCE_DEFECT | WAIVER_EXPIRED | BLOCKER |
| GOVERNANCE_DEFECT | WAIVER_MISSING | BLOCKER |
| GOVERNANCE_DEFECT | SCOPE_MISMATCH | BLOCKER |
| FORMAT_DEFECT | PARSE_ERROR | BLOCKER |
| FORMAT_DEFECT | SCHEMA_VIOLATION | BLOCKER |
| FORMAT_DEFECT | ID_FORMAT | MAJOR |
| FORMAT_DEFECT | SORT_ORDER | MINOR |
| FORMAT_DEFECT | DUPLICATE_ID | BLOCKER |
| FORMAT_DEFECT | TAB_CHARACTER | MINOR |
