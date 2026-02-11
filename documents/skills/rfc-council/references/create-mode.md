title: RFC CREATE Mode

decision_tree:
  entrypoint: CREATE_FLOW
  nodes[2]:
    - id: CREATE_FLOW
      purpose: "Generate RFC and tickets from PRD."
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <PRD_ID> and <RFC_ID> placeholders before running commands."
        - id: PHASE_1_GENESIS_CREATION
          action: |
            Initialize RFC v0 (Discovery):
            1. Create `documents/rfcs/RFC-XXXX/`
            2. Populate 00-09 YAML files from PRD content.
            3. Set `binds_to_prd` metadata.

        - id: PHASE_2_DISCOVERY_COUNCIL
          action: |
            Invoke COUNCIL_PROTOCOL with lifecycle-adaptive SA roles for v0:
            - SA-1: Focus on mapping PRD requirements to potential architecture.
            - SA-2: Identify implementability risks and missing codebase knowledge.
            - SA-3: Identify trust boundary gaps and security unknowns.

            Constraint: Each SA selects **2 Anchor + 3 Random** modes.

        - id: PHASE_2_5_TRANSCENDENTAL_ANCHOR
          action: |
            Perform **Mode 78 (Transcendental)** analysis on core PRD requirements:
            1. ANCHOR: State the requirement as an "Accepted Fact" (e.g., "The system must support X").
            2. QUESTION: Ask "What must be true in the existing architecture for X to be possible?"
            3. DERIVE: Infer non-negotiable preconditions.
            4. VALIDATE: If a precondition is missing in the current system, log it as a BLOCKER in 08_risks_and_open_questions.yaml.

        - id: PHASE_3_TICKET_CREATION
          condition: "mode is DECOMPOSE"
          action: |
            1. Transform `planned_ticket_structure` into `tickets` array in 06_ticket_decomposition.yaml.
            2. Map requirements, file paths, and acceptance criteria.
            3. Verify gates: ATOMICITY, IMPLEMENTABILITY, ANTI-COUSIN.
            4. Emit: `apm2 factory tickets emit --rfc RFC-XXXX --prd PRD-XXXX`.
            5. Commit changes.

        - id: PHASE_4_SELF_REVIEW
          condition: "mode is CREATE"
          action: |
            Execute REVIEW mode on v0:
            - Focus on GATE-TCK-SCOPE-COVERAGE and GATE-TCK-SCHEMA.
            - Accept failing gates for ATOMICITY/IMPLEMENTABILITY if documented as open questions in 08_risks_and_open_questions.yaml.

        - id: PHASE_5_COMMIT
          condition: "mode is CREATE"
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
            next: STOP

    - id: STOP
      purpose: "Terminate."
      steps[1]:
        - id: DONE
          action: "output DONE and nothing else, your task is complete."

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
