title: RFC Ticket Finding Categories

Taxonomy for RFC ticket review finding classification. Enables FindingSignature computation, recurrence tracking, and automated remediation recommendations.

---

## STRUCTURE_DEFECT

Defects in ticket structure and dependencies.

| Subcategory | Description | Gate Source |
|-------------|-------------|-------------|
| DEPENDENCY_CYCLE | Circular dependency in ticket graph | GATE-TCK-DEPENDENCY-ACYCLICITY |
| BROKEN_REF | Reference to non-existent ticket or requirement | GATE-TCK-SCHEMA |
| SCHEMA_VIOLATION | Ticket doesn't match schema | GATE-TCK-SCHEMA |
| PHASE_MISORDERING | Tickets ordered incorrectly for implementation | GATE-TCK-DEPENDENCY-ACYCLICITY |

---

## COVERAGE_DEFECT

Defects in requirement coverage.

| Subcategory | Description | Gate Source |
|-------------|-------------|-------------|
| SCOPE_GAP | RFC requirement not covered by any ticket | GATE-TCK-SCOPE-COVERAGE |
| ORPHAN_TICKET | Ticket doesn't map to any RFC requirement | GATE-TCK-SCOPE-COVERAGE |
| SCOPE_OVERLAP | Multiple tickets cover same requirement without coordination | GATE-TCK-SCOPE-COVERAGE |
| EVIDENCE_GAP | Ticket missing required evidence link | GATE-TCK-SCOPE-COVERAGE |

---

## COUSIN_DEFECT

Anti-cousin violations - the most critical defect category for architectural health.

| Subcategory | Description | Gate Source |
|-------------|-------------|-------------|
| COUSIN_VIOLATION | New code duplicates existing pattern | GATE-TCK-ANTI-COUSIN |
| CCP_MISMATCH | File path not in CCP component atlas | GATE-TCK-CCP-MAPPING |
| IGNORED_EXTENSION_POINT | Existing extension mechanism not used | GATE-TCK-ANTI-COUSIN |
| DECISION_CONFLICT | Ticket contradicts RFC design decision | GATE-TCK-ANTI-COUSIN |

---

## IMPLEMENTABILITY_DEFECT

Defects that prevent agent implementation.

| Subcategory | Description | Gate Source |
|-------------|-------------|-------------|
| INCOMPLETE_PLAN | Implementation steps missing or unclear | GATE-TCK-IMPLEMENTABILITY |
| MISSING_VERIFICATION | No verification method specified | GATE-TCK-IMPLEMENTABILITY |
| AGENT_CONTEXT_GAP | Agent lacks information to implement | GATE-TCK-IMPLEMENTABILITY |
| AMBIGUOUS_SCOPE | Unclear what exactly to implement | GATE-TCK-IMPLEMENTABILITY |

---

## ATOMICITY_DEFECT

Defects in ticket atomicity and PR mergability.

| Subcategory | Description | Gate Source |
|-------------|-------------|-------------|
| ATOMICITY_VIOLATION | Ticket cannot be completed in single PR | GATE-TCK-ATOMICITY |
| SCOPE_TOO_LARGE | Ticket modifies too many files/components | GATE-TCK-ATOMICITY |
| MULTI_COMPONENT | Ticket spans more than 2 components | GATE-TCK-ATOMICITY |
| MERGE_UNSAFE | Merging ticket alone would break system | GATE-TCK-ATOMICITY |

---

## SECURITY_DEFECT

Defects in security posture and trust boundary preservation.

| Subcategory | Description | Gate Source |
|-------------|-------------|-------------|
| BOUNDARY_VIOLATION | Ticket crosses trust boundary without validation | GATE-TCK-SECURITY-AND-INTEGRITY |
| INVARIANT_FAILURE | Ticket violates a system security invariant | GATE-TCK-SECURITY-AND-INTEGRITY |
| UNMITIGATED_THREAT | Identified threat (TH-XXX) lacks implementation | GATE-TCK-SECURITY-AND-INTEGRITY |
| SECRET_EXPOSURE | Potential for credential leakage or exposure | GATE-TCK-SECURITY-AND-INTEGRITY |

---

## FIDELITY_DEFECT

Defects in how implementation matches requirement intent.

| Subcategory | Description | Gate Source |
|-------------|-------------|-------------|
| REQUIREMENT_GAP | Implementation fails to fulfill core requirement | GATE-TCK-REQUIREMENT-FIDELITY |
| INTENT_MISMATCH | Implementation substance contradicts PRD intent | GATE-TCK-REQUIREMENT-FIDELITY |
| ANOMALY_IGNORED | Implementation fails to address listed anomaly | GATE-TCK-REQUIREMENT-FIDELITY |
| INSUFFICIENT_SUBSTANCE | Steps are logically insufficient for success | GATE-TCK-REQUIREMENT-FIDELITY |

---

## FindingSignature

Deterministic signature for recurrence tracking. Computed as `blake3(json({category, subcategory, gate_id, location_type}))[:16]`.

**Fields:**
- `category`: One of the five categories above (e.g., COUSIN_DEFECT)
- `subcategory`: Specific defect type within category (e.g., CCP_MISMATCH)
- `gate_id`: The gate that detected it (e.g., GATE-TCK-CCP-MAPPING)
- `location_type`: The type of file where finding occurred: `TICKET`, `RFC`, `CCP`

**Properties:** Deterministic, content-based (not instance-based), stable across location changes within same location_type.

---

## Severity Assignment Rules

Severity is determined by category and subcategory combination.

| Category | Subcategory | Default Severity |
|----------|-------------|------------------|
| STRUCTURE_DEFECT | DEPENDENCY_CYCLE | BLOCKER |
| STRUCTURE_DEFECT | BROKEN_REF | BLOCKER |
| STRUCTURE_DEFECT | SCHEMA_VIOLATION | BLOCKER |
| STRUCTURE_DEFECT | PHASE_MISORDERING | MAJOR |
| COVERAGE_DEFECT | SCOPE_GAP | BLOCKER |
| COVERAGE_DEFECT | ORPHAN_TICKET | MAJOR |
| COVERAGE_DEFECT | SCOPE_OVERLAP | MINOR |
| COVERAGE_DEFECT | EVIDENCE_GAP | MAJOR |
| COUSIN_DEFECT | COUSIN_VIOLATION | BLOCKER |
| COUSIN_DEFECT | CCP_MISMATCH | BLOCKER |
| COUSIN_DEFECT | IGNORED_EXTENSION_POINT | MAJOR |
| COUSIN_DEFECT | DECISION_CONFLICT | BLOCKER |
| IMPLEMENTABILITY_DEFECT | INCOMPLETE_PLAN | BLOCKER |
| IMPLEMENTABILITY_DEFECT | MISSING_VERIFICATION | MAJOR |
| IMPLEMENTABILITY_DEFECT | AGENT_CONTEXT_GAP | MAJOR |
| IMPLEMENTABILITY_DEFECT | AMBIGUOUS_SCOPE | MAJOR |
| ATOMICITY_DEFECT | ATOMICITY_VIOLATION | BLOCKER |
| ATOMICITY_DEFECT | SCOPE_TOO_LARGE | MAJOR |
| ATOMICITY_DEFECT | MULTI_COMPONENT | MAJOR |
| ATOMICITY_DEFECT | MERGE_UNSAFE | BLOCKER |
| SECURITY_DEFECT | BOUNDARY_VIOLATION | BLOCKER |
| SECURITY_DEFECT | INVARIANT_FAILURE | MAJOR |
| SECURITY_DEFECT | UNMITIGATED_THREAT | MAJOR |
| SECURITY_DEFECT | SECRET_EXPOSURE | BLOCKER |
| FIDELITY_DEFECT | REQUIREMENT_GAP | BLOCKER |
| FIDELITY_DEFECT | INTENT_MISMATCH | MAJOR |
| FIDELITY_DEFECT | ANOMALY_IGNORED | MAJOR |
| FIDELITY_DEFECT | INSUFFICIENT_SUBSTANCE | MAJOR |

---

## Recurrence Thresholds

| Occurrences | Action |
|-------------|--------|
| 3 | Flag for countermeasure consideration |
| 5 | Auto-create countermeasure work item |
| 10 | Escalate to human review |

---

## Remediation Patterns

### COUSIN_VIOLATION Remediation

```yaml
remediation:
  pattern: EXTEND_EXISTING
  steps:
    - Identify existing abstraction to extend
    - Document extension point used
    - Update CCP with new usage
    - Remove duplicate code
```

### INCOMPLETE_PLAN Remediation

```yaml
remediation:
  pattern: ADD_IMPLEMENTATION_DETAIL
  steps:
    - Add specific file paths
    - Add function signatures
    - Add code examples
    - Add verification commands
```

### ATOMICITY_VIOLATION Remediation

```yaml
remediation:
  pattern: SPLIT_TICKET
  steps:
    - Identify independent units of work
    - Create separate tickets for each
    - Establish dependencies
    - Verify each is atomically mergable
```

---

## References

- [REVIEW_RUBRIC.md](REVIEW_RUBRIC.md) - Gate definitions
- [COUNCIL_PROTOCOL.md](COUNCIL_PROTOCOL.md) - Multi-agent deliberation
