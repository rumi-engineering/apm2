title: RFC Ticket Review Rubric

Formal gate definitions with evidence contracts for RFC ticket review.

## Gate Overview

Gates are executed in order. Deterministic gates run before LLM-assisted gates to catch structural issues early.

**Gate Type Definitions:**
- **TRUSTED**: Tool-based validation (YAML parsers) - deterministic and machine-verifiable
- **DETERMINISTIC**: Algorithmic checks (graph traversal, counting) - no LLM judgment required
- **LLM-ASSISTED**: Semantic analysis requiring LLM judgment - results are UNTRUSTED until human confirms

| Gate ID | Type | Purpose |
|---------|------|---------|
| GATE-TCK-SCHEMA | TRUSTED | YAML parsing and schema conformance |
| GATE-TCK-DEPENDENCY-ACYCLICITY | DETERMINISTIC | No cycles in ticket dependency graph |
| GATE-TCK-SCOPE-COVERAGE | DETERMINISTIC | All RFC requirements covered by tickets |
| GATE-TCK-CCP-MAPPING | DETERMINISTIC | File paths exist in CCP (anti-cousin) |
| GATE-TCK-ATOMICITY | LLM-ASSISTED | Each ticket completable in single PR |
| GATE-TCK-IMPLEMENTABILITY | LLM-ASSISTED | Agent can implement without clarification |
| GATE-TCK-SECURITY-AND-INTEGRITY | LLM-ASSISTED | Tickets preserve trust boundaries and mitigate threats |
| GATE-TCK-REQUIREMENT-FIDELITY | LLM-ASSISTED | Implementation content accurately fulfills PRD intent |
| GATE-TCK-ANTI-COUSIN | LLM-ASSISTED | No cousin abstractions introduced |

---

## GATE-TCK-SCHEMA

**Type:** TRUSTED (deterministic, no LLM)

### Purpose

Verify all ticket files parse as valid YAML and conform to ticket schema.

### Evidence Contract

| Field | Value |
|-------|-------|
| Inputs | All ticket YAML files in `documents/work/tickets/TCK-*.yaml` filtered by `rfc_id` |
| Outputs | Parse results, schema validation results |
| Required | All files parse without error, all files validate against schema |

### Rubric

| Check | Pass Criteria | Tool |
|-------|---------------|------|
| YAML parse | All files parse without syntax errors | Read each file |
| Required fields | Each ticket has: id, title, status, rfc_id | Check structure |
| ID format | Ticket ID matches `TCK-[0-9]{5}` | Regex validation |
| Status valid | Status is one of: READY, IN_PROGRESS, COMPLETED | Enum check |
| No tabs | Files contain no tab characters | Grep for tabs |

### Verification Steps

```bash
# Check all ticket files parse
for f in documents/work/tickets/TCK-*.yaml; do
  python3 -c "import yaml; yaml.safe_load(open('$f'))" || echo "FAILED: $f"
done

# Check required fields
for f in documents/work/tickets/TCK-*.yaml; do
  grep -q "^  id:" "$f" || echo "MISSING id: $f"
  grep -q "^  title:" "$f" || echo "MISSING title: $f"
  grep -q "^  status:" "$f" || echo "MISSING status: $f"
  grep -q "^  rfc_id:" "$f" || echo "MISSING rfc_id: $f"
done
```

### Stop Condition

FAILED if any file fails to parse or missing required fields.

---

## GATE-TCK-DEPENDENCY-ACYCLICITY

**Type:** DETERMINISTIC (algorithmic, no LLM)

### Purpose

Verify ticket dependency graph has no cycles. Cycles indicate impossible execution order.

### Evidence Contract

| Field | Value |
|-------|-------|
| Inputs | All ticket files with `depends_on` fields |
| Outputs | Dependency graph, cycle detection result |
| Required | No cycles detected in dependency graph |

### Rubric

| Check | Pass Criteria |
|-------|---------------|
| Build graph | Extract all ticket IDs and their depends_on lists |
| Topological sort | Graph can be topologically sorted |
| No cycles | DFS detects no back edges |
| Valid references | All depends_on IDs reference existing tickets |

### Algorithm

```python
def detect_cycles(tickets):
    graph = {t.id: t.depends_on for t in tickets}
    visited = set()
    rec_stack = set()

    def dfs(node):
        visited.add(node)
        rec_stack.add(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                if dfs(neighbor):
                    return True  # Cycle found
            elif neighbor in rec_stack:
                return True  # Back edge = cycle
        rec_stack.remove(node)
        return False

    for node in graph:
        if node not in visited:
            if dfs(node):
                return True  # FAILED
    return False  # PASSED
```

### Stop Condition

FAILED if any cycle detected in dependency graph.

---

## GATE-TCK-SCOPE-COVERAGE

**Type:** DETERMINISTIC (algorithmic, no LLM)

### Purpose

Verify all RFC requirements are covered by at least one ticket.

### Evidence Contract

| Field | Value |
|-------|-------|
| Inputs | RFC `01_problem_and_imports.yaml`, all ticket files |
| Outputs | Coverage matrix, uncovered requirements |
| Required | Every requirement_id has at least one ticket |

### Rubric

| Check | Pass Criteria |
|-------|---------------|
| Extract requirements | Get all requirement IDs from RFC |
| Extract ticket coverage | Get all requirement_ids from tickets |
| Coverage check | Every RFC requirement appears in at least one ticket |
| No orphan tickets | Every ticket references at least one valid requirement |

### Verification Steps

```bash
# Extract RFC requirements
RFC_REQS=$(grep -oE "(REQ|MAINT|FEAT|SEC|PERF)-[0-9]{3,4}" documents/rfcs/{RFC_ID}/01_problem_and_imports.yaml | sort -u)

# Extract ticket coverage
TICKET_REQS=$(grep -rh "requirement_ids:" -A 20 documents/work/tickets/TCK-*.yaml | grep -oE "(REQ|MAINT|FEAT|SEC|PERF)-[0-9]{3,4}" | sort -u)

# Find uncovered requirements
UNCOVERED=$(comm -23 <(echo "$RFC_REQS") <(echo "$TICKET_REQS"))
[ -n "$UNCOVERED" ] && echo "UNCOVERED: $UNCOVERED"
```

### Stop Condition

FAILED if any RFC requirement has no covering ticket.

---

## GATE-TCK-CCP-MAPPING

**Type:** DETERMINISTIC (algorithmic, no LLM)

### Purpose

Verify all file paths in tickets exist in CCP (Codebase Component Protocol). This is the primary anti-cousin gate.

### Evidence Contract

| Field | Value |
|-------|-------|
| Inputs | All ticket `files_to_modify` and `files_to_create`, CCP component atlas |
| Outputs | Path mapping results, unmapped paths |
| Required | All file paths map to CCP OR have cousin justification |

### Rubric

| Check | Pass Criteria |
|-------|---------------|
| Extract paths | Get all file paths from tickets |
| Load CCP | Load `evidence/prd/{PRD_ID}/ccp/component_atlas.yaml` |
| Map paths | Every path must exist in CCP known_files OR be in allowed_new_files |
| files_to_modify | Must already exist in CCP |
| files_to_create | Must be in a known CCP component directory |

### Verification Steps

```python
def verify_ccp_mapping(tickets, ccp):
    unmapped = []
    for ticket in tickets:
        for f in ticket.files_to_modify:
            if f.path not in ccp.known_files:
                unmapped.append((ticket.id, f.path, "MODIFY"))
        for f in ticket.files_to_create:
            if not any(f.path.startswith(c) for c in ccp.component_dirs):
                unmapped.append((ticket.id, f.path, "CREATE"))
    return unmapped
```

### Cousin Justification

If a path cannot be mapped to CCP, a cousin justification is required:

```yaml
cousin_justification:
  ticket_id: TCK-XXXXX
  file_path: "path/to/new_file.rs"
  existing_component: "path/to/similar/component"
  capability_gap: "Specific capability that is missing"
  evidence_artifact: "EVID-XXXX"
  decision: EXTEND | CREATE_NEW
  decision_rationale: "Why extension is insufficient"
```

### Stop Condition

FAILED if any path unmapped AND no valid cousin justification.

---

## GATE-TCK-ATOMICITY

**Type:** LLM-ASSISTED (semantic analysis, UNTRUSTED)

### Purpose

Verify each ticket can be completed in a single PR without requiring other tickets.

### Evidence Contract

| Field | Value |
|-------|-------|
| Inputs | All ticket implementation sections |
| Outputs | Atomicity assessment per ticket |
| Required | Each ticket is atomic (single PR completable) |

### Rubric

| Check | Pass Criteria |
|-------|---------------|
| Single concern | Ticket addresses one cohesive change |
| File count | Ticket modifies <= 10 files |
| Component count | Ticket touches <= 2 crates/components |
| Test completeness | Ticket includes all tests needed to verify itself |
| No partial state | Ticket doesn't leave system in broken state if merged alone |

### Assessment Questions

For each ticket:
1. Can this be implemented in a single PR?
2. Would merging this alone break the system?
3. Are all tests for this change included in this ticket?
4. Does this ticket depend on changes from other tickets?

### Severity Assignment

| Issue | Severity |
|-------|----------|
| Ticket requires multiple PRs | BLOCKER |
| Ticket touches >2 components | MAJOR |
| Ticket missing verification tests | MAJOR |
| Ticket scope could be split | MINOR |

### Stop Condition

FAILED if any ticket cannot be atomically merged.

---

## GATE-TCK-IMPLEMENTABILITY

**Type:** LLM-ASSISTED (semantic analysis, UNTRUSTED)

### Purpose

Verify an agent can implement each ticket without requiring clarification.

### Evidence Contract

| Field | Value |
|-------|-------|
| Inputs | All ticket implementation sections, code examples |
| Outputs | Implementability assessment per ticket |
| Required | Agent can implement without asking questions |

### Rubric

| Check | Pass Criteria |
|-------|---------------|
| Clear steps | Implementation steps are unambiguous |
| Sufficient context | Agent has all information needed |
| Code examples | Examples show exact patterns to follow |
| Verification | Agent knows how to verify success |
| Error handling | Error cases are documented |

### Assessment Questions

For each ticket, ask from agent perspective:
1. Do I know exactly what code to write?
2. Do I know where to put the code?
3. Do I understand the expected behavior?
4. Do I know how to test this?
5. Do I need to ask any clarifying questions?

### Implementability Checklist

- [ ] File paths are absolute and unambiguous
- [ ] Function signatures are specified
- [ ] Data types are clear
- [ ] Edge cases are documented
- [ ] Success criteria are measurable
- [ ] Verification commands are provided

### Severity Assignment

| Issue | Severity |
|-------|----------|
| Missing implementation steps | BLOCKER |
| Ambiguous file paths | BLOCKER |
| No verification method | MAJOR |
| Missing error handling | MAJOR |
| Vague acceptance criteria | MAJOR |
| Minor clarity improvements | MINOR |

### Stop Condition

FAILED if any ticket has BLOCKER implementability issues.

---

## GATE-TCK-SECURITY-AND-INTEGRITY

**Type:** LLM-ASSISTED (semantic analysis, UNTRUSTED)

### Purpose

Verify that the ticket-level implementation details respect the trust boundaries, invariants, and threat mitigations defined in the RFC.

### Evidence Contract

| Field | Value |
|-------|-------|
| Inputs | Ticket implementation steps, `03_trust_boundaries.yaml`, SA-3 CAE Tree |
| Outputs | Security integrity assessment per ticket |
| Required | No violation of defined trust boundaries or invariants |

### Rubric

| Check | Pass Criteria |
|-------|---------------|
| Trust Boundary | Ticket steps do not cross boundaries without validation |
| Invariant Preservation | Implementation maintains all listed boundary invariants |
| Threat Mitigation | Ticket includes steps for relevant TH-XXX mitigations |
| Secret Handling | No hardcoded secrets or insecure credential patterns |

### Assessment Questions (from SA-3)

1. Does this ticket introduce a new interface that crosses a trust boundary (e.g., untrusted model output)?
2. If so, are there explicit validation steps in the implementation?
3. Does the ticket maintain the "Atomic writes" invariant (e.g., using `NamedTempFile`)?
4. Are there any exploitation vectors (TH-XXX) that this ticket fails to address?

### Severity Assignment

| Issue | Severity |
|-------|----------|
| Trust boundary violation | BLOCKER |
| Failed invariant (e.g., non-atomic write) | MAJOR |
| Missing mitigation for identified threat | MAJOR |
| Insecure error handling (leaking info) | MINOR |

---

## GATE-TCK-REQUIREMENT-FIDELITY

**Type:** LLM-ASSISTED (semantic analysis, UNTRUSTED)

### Purpose

Verify that the *substance* of the tickets (implementation steps and code examples) actually solves the problem described in the PRD, rather than just "referencing" the requirement ID.

### Evidence Contract

| Field | Value |
|-------|-------|
| Inputs | Ticket content, `01_problem_and_imports.yaml`, SA-1 Abductive Scoring Table |
| Outputs | Fidelity score per requirement mapping |
| Required | Implementation steps are logically sufficient to fulfill the requirement |

### Rubric

| Check | Pass Criteria |
|-------|---------------|
| Logical Sufficiency | Steps fully implement the "Problem Statement" intent |
| Requirement Alignment | Code examples match the imported requirement definitions |
| No Scope Gap | No "middle-of-the-road" implementations that miss the core need |

### Assessment Questions (from SA-1)

1. Looking at the PRD requirement, would these implementation steps actually fulfill it?
2. Is the "Best Explanation" from the Abductive Scoring Table reflected in the ticket's design choices?
3. Does the ticket address the "Surprising observations" or "Anomalies" listed in the problem statement?

### Severity Assignment

| Issue | Severity |
|-------|----------|
| Implementation fails to solve core PRD problem | BLOCKER |
| Significant gap between requirement and steps | MAJOR |
| Code example contradicts requirement intent | MAJOR |
| Implementation is correct but inefficient | MINOR |

---

## GATE-TCK-ANTI-COUSIN

**Type:** LLM-ASSISTED (semantic analysis, UNTRUSTED)

### Purpose

Verify no ticket introduces cousin abstractions - new code that duplicates existing patterns.

### Evidence Contract

| Field | Value |
|-------|-------|
| Inputs | Ticket code examples, CCP component atlas, existing codebase |
| Outputs | Cousin analysis per ticket |
| Required | No unjustified cousin abstractions |

### Rubric

| Check | Pass Criteria |
|-------|---------------|
| Pattern search | Proposed code compared to existing patterns |
| Reuse check | Existing utilities/traits considered |
| Extension points | Existing extension mechanisms used |
| Justification | New abstractions justified with evidence |

### Assessment Questions

For each ticket:
1. Does similar code already exist?
2. Could this extend an existing abstraction?
3. Is there a trait/interface this should implement?
4. Would this create a parallel hierarchy?

### Anti-Cousin Patterns to Check

1. **Utility duplication**: New helper that duplicates existing utility
2. **Trait divergence**: New trait similar to existing trait
3. **Pattern reinvention**: Reimplementing established pattern differently
4. **Parallel hierarchies**: Creating new type hierarchy parallel to existing

### Severity Assignment

| Issue | Severity |
|-------|----------|
| Clear cousin abstraction | BLOCKER |
| Missed extension point | MAJOR |
| Parallel pattern | MAJOR |
| Minor duplication | MINOR |

### Stop Condition

FAILED if any unjustified cousin abstraction detected.

---

## Output Schemas

### Evidence Bundle (minimal)

```yaml
schema_version: "1.0.0"
rfc_id: RFC-XXXX
review_timestamp: "2026-01-26T10:00:00Z"
gates:
  - gate_id: GATE-TCK-SCHEMA
    type: TRUSTED
    status: PASSED
    findings: []
    evidence: {}
findings: []
verdict: APPROVED
verdict_reason: "All gates passed"
```

### Finding

```yaml
finding_id: FND-RFC-XXXX-001
gate_id: GATE-TCK-IMPLEMENTABILITY
category: IMPLEMENTABILITY_DEFECT
subcategory: INCOMPLETE_PLAN
severity: MAJOR
location:
  file: documents/work/tickets/TCK-00101.yaml
  yaml_path: implementation.implementation_steps
description: "Implementation steps missing error handling"
remediation: "Add error handling steps for network failures"
signature: "abc123..."
```

### Severity Levels

| Severity | Impact |
|----------|--------|
| BLOCKER | Gate FAILED, review stops |
| MAJOR | Must remediate before approval |
| MINOR | Should remediate |
| INFO | Optional improvement |
