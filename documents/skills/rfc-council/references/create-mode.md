title: RFC CREATE Mode

decision_tree:
  entrypoint: CREATE_FLOW
  nodes[1]:
    - id: CREATE_FLOW
      purpose: "Generate RFC and tickets from PRD."
      steps[5]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <PRD_ID> and <RFC_ID> placeholders before running commands."
        - id: PHASE_1_GENESIS_CREATION
          action: |
            Create RFC directory and 9 YAML files for v0 (Discovery):

            1. Create directory: documents/rfcs/RFC-XXXX/

            2. Generate 9 files from PRD content:
               - 00_meta.yaml: Set version: v0. metadata, status (DRAFT).
               - 01_problem_and_imports.yaml: Problem statement, requirements (from PRD).
               - 02_design_decisions.yaml: Initial design hypotheses.
               - 03_trust_boundaries.yaml: Identified security surface area.
               - 04_contracts_and_versioning.yaml: Tentative interface definitions.
               - 05_rollout_and_ops.yaml: High-level rollout strategy.
               - 06_ticket_decomposition.yaml: Placeholder for future decomposition.
               - 07_test_and_evidence.yaml: Test strategy hypotheses.
               - 08_risks_and_open_questions.yaml: CRITICAL: List all "Known Unknowns" and codebase discovery needs.
               - 09_governance_and_gates.yaml: Initial gate configuration.

            3. Link to PRD:
               binds_to_prd:
                 prd_id: PRD-XXXX
                 rationale: "Initiates RFC v0 discovery for PRD requirements"

        - id: PHASE_2_DISCOVERY_COUNCIL
          action: |
            Invoke COUNCIL_PROTOCOL with specialized SA roles for v0:
            - SA-1: Focus on mapping PRD requirements to potential architecture.
            - SA-2: Identify implementability risks and missing codebase knowledge.
            - SA-3: Identify trust boundary gaps and security unknowns.

            Constraint: Each SA selects 3 RANDOM reasoning modes + 5 specialized modes.

        - id: PHASE_4_SELF_REVIEW
          action: |
            Execute REVIEW mode on v0:
            - Focus on GATE-TCK-SCOPE-COVERAGE and GATE-TCK-SCHEMA.
            - Accept failing gates for ATOMICITY/IMPLEMENTABILITY if documented as open questions in 08_risks_and_open_questions.yaml.

        - id: PHASE_5_COMMIT
          action: |
            Stage and commit:
            ```bash
            git add documents/rfcs/RFC-XXXX/
            git commit -m "docs(RFC-XXXX): Initialize RFC v0 Discovery phase"
            ```
      decisions[1]:
        - id: FINISHED
          if: "always"
          then:
            stop: true

---

## RFC Document Structure

Each RFC consists of 9 YAML files in `documents/rfcs/RFC-XXXX/`:

| File | Purpose |
|------|---------|
| `00_meta.yaml` | RFC metadata, status, custody, key dependencies |
| `01_problem_and_imports.yaml` | Problem statement, requirements |
| `02_design_decisions.yaml` | Design choices with alternatives and rationale |
| `03_trust_boundaries.yaml` | Trust boundaries and security considerations |
| `04_contracts_and_versioning.yaml` | API contracts, versioning strategy |
| `05_rollout_and_ops.yaml` | Rollout plan, operational considerations |
| `06_ticket_decomposition.yaml` | Engineering tickets with implementation details |
| `07_test_and_evidence.yaml` | Test strategy, evidence requirements |
| `08_risks_and_open_questions.yaml` | Risks, open questions |
| `09_governance_and_gates.yaml` | Gate reviews, approval requirements |

## Ticket Structure

```yaml
schema_version: "2026-01-25"
template_version: "2026-01-25"

ticket:
  id: TCK-XXXXX
  title: "Ticket title"
  status: READY
  rfc_id: RFC-XXXX
  requirement_ids:
    - REQ-XXX
  depends_on: []  # Other ticket IDs

implementation:
  summary: |
    Brief description of what this ticket implements.

  files_to_modify:
    - path: "path/to/file.rs"
      changes: "Description of changes"

  files_to_create:
    - path: "path/to/new_file.rs"
      purpose: "Purpose of new file"

  implementation_steps:
    - step: 1
      action: "Description of step"
      details: |
        Detailed implementation guidance...

  code_examples:
    - description: "Example description"
      code: |
        // Code snippet

acceptance_criteria:
  - criterion: "Criterion 1"
    verification: "How to verify"

test_requirements:
  - test_id: UT-XXX-XXX
    description: "Test description"
    verification_command: "cargo test ..."

notes: |
  Additional notes or context.
```

## Common Patterns

### Maintenance RFC (no PRD)

```yaml
binds_to_prd:
  prd_id: "NONE"
  rationale: "Maintenance RFC improving existing tooling"
```

### Requirement ID Prefixes

- `MAINT-XXX`: Maintenance/improvement requirements
- `FEAT-XXX`: Feature requirements
- `SEC-XXX`: Security requirements
- `PERF-XXX`: Performance requirements

### Ticket Status Flow

```
READY -> IN_PROGRESS -> COMPLETED
```
