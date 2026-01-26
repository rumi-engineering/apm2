title: RFC CREATE Mode

decision_tree:
  entrypoint: CREATE_FLOW
  nodes[1]:
    - id: CREATE_FLOW
      purpose: "Generate RFC and tickets from PRD."
      steps[7]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <PRD_ID> and <RFC_ID> placeholders before running commands."
        - id: PHASE_1_RFC_CREATION
          action: |
            Create RFC directory and 9 YAML files:

            1. Create directory: documents/rfcs/RFC-XXXX/

            2. Generate 9 files from PRD content:
               - 00_meta.yaml: RFC metadata, status (DRAFT), custody, implementation details
               - 01_problem_and_imports.yaml: Problem statement, requirements (from PRD)
               - 02_design_decisions.yaml: Design choices with alternatives and rationale
               - 03_trust_boundaries.yaml: Trust boundaries and security considerations
               - 04_contracts_and_versioning.yaml: API contracts, versioning strategy
               - 05_rollout_and_ops.yaml: Rollout plan, operational considerations
               - 06_ticket_decomposition.yaml: Engineering tickets with implementation details
               - 07_test_and_evidence.yaml: Test strategy, evidence requirements
               - 08_risks_and_open_questions.yaml: Risks, open questions
               - 09_governance_and_gates.yaml: Gate reviews, approval requirements

            3. Link to PRD:
               binds_to_prd:
                 prd_id: PRD-XXXX
                 rationale: "Implements PRD requirements"

        - id: PHASE_2_QUALITY_REVIEW
          action: |
            Spawn subagents for iterative quality review:

            Pass 1 - Completeness:
            - Check for missing sections
            - Verify file paths reference actual codebase files
            - Ensure requirements map to tickets

            Pass 2 - Consistency:
            - Check for contradictions between files
            - Verify terminology consistency
            - Validate code snippets are syntactically correct

            Pass 3 - Anti-Cousin:
            - Verify all file paths exist in CCP
            - Check for reuse opportunities
            - Validate no cousin abstractions

        - id: PHASE_3_TICKET_CREATION
          action: |
            Create ticket files from 06_ticket_decomposition.yaml:

            For each ticket:
            1. Create documents/work/tickets/TCK-XXXXX.yaml
            2. Structure:
               ```yaml
               schema_version: "2026-01-25"
               template_version: "2026-01-25"

               ticket:
                 id: TCK-XXXXX
                 title: "Ticket title"
                 status: READY
                 rfc_id: RFC-XXXX
                 requirement_ids: [REQ-XXX]
                 depends_on: []

               implementation:
                 summary: "Brief description"
                 files_to_modify: []
                 files_to_create: []
                 implementation_steps: []
                 code_examples: []

               acceptance_criteria: []
               test_requirements: []
               ```

            Spawn parallel subagents (up to 9) for ticket creation.

        - id: PHASE_4_SELF_REVIEW
          action: |
            Execute REVIEW mode on generated RFC/tickets:
            - Run all 7 gates
            - Fix any BLOCKER findings
            - Document MAJOR findings for human review

        - id: PHASE_5_COMMIT
          action: |
            Stage and commit:
            ```bash
            git add documents/rfcs/RFC-XXXX/ documents/work/tickets/TCK-*.yaml
            git commit -m "docs(RFC-XXXX): RFC title and engineering tickets"
            ```

        - id: PHASE_6_PR
          action: |
            Push and create PR:
            ```bash
            git push -u origin HEAD
            gh pr create --title "docs(RFC-XXXX): RFC Title" --body "..."
            ```

            For RFC docs (no executable code), manually set AI review statuses:
            ```bash
            SHA=$(gh pr view <PR> --json headRefOid --jq '.headRefOid')
            gh api repos/{owner}/{repo}/statuses/$SHA -f state=success -f context=ai-review/security
            gh api repos/{owner}/{repo}/statuses/$SHA -f state=success -f context=ai-review/code-quality
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
