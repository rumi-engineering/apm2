title: RFC CREATE Mode

# Execution Context
#
# This file serves two modes with conditional execution:
# - CREATE mode: Executes PHASE_1 -> PHASE_2 -> PHASE_4 -> PHASE_5 (skips PHASE_3)
# - DECOMPOSE mode: Jumps directly to PHASE_3 only (ticket generation)
#
# The `condition` field on each step indicates which mode(s) execute it.
# Steps without a condition are executed by all modes.

decision_tree:
  entrypoint: CREATE_FLOW
  nodes[1]:
    - id: CREATE_FLOW
      purpose: "Generate RFC and tickets from PRD. Also handles DECOMPOSE mode for ticket generation."
      steps[6]:
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
            Invoke COUNCIL_PROTOCOL with lifecycle-adaptive SA roles for v0:
            - SA-1: Focus on mapping PRD requirements to potential architecture.
            - SA-2: Identify implementability risks and missing codebase knowledge.
            - SA-3: Identify trust boundary gaps and security unknowns.

            Constraint: Each SA selects **5 strictly random reasoning modes** from modes-of-reasoning
            (see COUNCIL_PROTOCOL.md Step 3: Stochastic Mode Selection for algorithm).

        - id: PHASE_3_TICKET_CREATION
          condition: "mode is DECOMPOSE"
          action: |
            Generate engineering tickets from approved RFC v4:
            (DECOMPOSE mode jumps directly to this step via rfc-council-workflow.md)

            Prerequisites:
            - RFC is at version v4 (Standard phase)
            - 06_ticket_decomposition.yaml has planned_ticket_structure

            ## Step 1: Populate Ticket Decomposition

            Transform `planned_ticket_structure` into full `tickets` array in 06_ticket_decomposition.yaml:

            For each ticket group in planned_ticket_structure:
            1. Generate stable ticket ID (TCK-XXXXX where XXXXX is sequential)
            2. Extract implementation details from RFC design decisions (02_design_decisions.yaml)
            3. Map requirements from the group to the ticket
            4. Define file paths (files_to_create, files_to_modify) from CCP analysis
            5. Write acceptance criteria from test strategy (07_test_and_evidence.yaml)
            6. Set depends_on based on logical ordering (types before reducer before controller)

            Update 06_ticket_decomposition.yaml:
            ```yaml
            status: POPULATED
            tickets:
              - ticket_id: TCK-XXXXX
                title: "..."
                requirement_ids: [REQ-...]
                depends_on: []
                files_to_create: [...]
                files_to_modify: [...]
                implementation_steps: [...]
                acceptance_criteria: [...]
                test_requirements: [...]
            ```

            ## Step 2: Validate Gates

            Before emission, verify:
            - GATE-TCK-ATOMICITY: Each ticket is single-PR completable
            - GATE-TCK-IMPLEMENTABILITY: Agent can implement without ambiguity
            - GATE-TCK-ANTI-COUSIN: No duplicate patterns introduced

            ## Step 3: Emit Tickets via CLI

            Delegate file generation to the CLI:
            ```bash
            apm2 factory tickets emit --rfc RFC-XXXX --prd PRD-XXXX
            ```

            This reads the populated 06_ticket_decomposition.yaml and generates
            individual ticket files to documents/work/tickets/TCK-*.yaml.

            ## Step 4: Commit

            Stage and commit all changes:
            ```bash
            git add documents/rfcs/RFC-XXXX/06_ticket_decomposition.yaml
            git add documents/work/tickets/TCK-*.yaml
            git commit -m "docs(RFC-XXXX): Generate engineering tickets from v4"
            ```

            Return to caller (do not proceed to PHASE_4/PHASE_5).

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
