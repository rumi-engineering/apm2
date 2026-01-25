# Create RFC Skill

This skill documents the process for creating RFC (Request for Comments) documents in the apm2 project.

## Prerequisites

- Familiarity with YAML syntax
- Understanding of the project's RFC structure
- Access to spawn subagents for quality review and ticket creation

## Orientation

Before writing an RFC, read these documents to understand the structure and expectations:

### Required Reading

1. **Existing RFC for reference**: Read `documents/rfcs/RFC-0005/` to understand the 9-file structure
2. **RFC Template** (if available): Check for any RFC templates in the project
3. **Plan file**: If a plan exists (e.g., in `.claude/plans/`), use it as the source of requirements

### RFC Document Structure

Each RFC consists of 9 YAML files in `documents/rfcs/RFC-XXXX/`:

| File | Purpose |
|------|---------|
| `00_meta.yaml` | RFC metadata, status, custody, key dependencies |
| `01_problem_and_imports.yaml` | Problem statement, requirements (MAINT-XXX, FEAT-XXX, etc.) |
| `02_design_decisions.yaml` | Design choices with alternatives and rationale |
| `03_trust_boundaries.yaml` | Trust boundaries and security considerations |
| `04_contracts_and_versioning.yaml` | API contracts, versioning strategy |
| `05_rollout_and_ops.yaml` | Rollout plan, operational considerations |
| `06_ticket_decomposition.yaml` | Engineering tickets with implementation details |
| `07_test_and_evidence.yaml` | Test strategy, unit/integration tests, evidence requirements |
| `08_risks_and_open_questions.yaml` | Risks, open questions, decisions needed |
| `09_governance_and_gates.yaml` | Gate reviews, approval requirements |

## Step-by-Step Process

### Phase 1: Initial RFC Creation

1. **Create RFC directory**:
   ```bash
   mkdir -p documents/rfcs/RFC-XXXX
   ```

2. **Create all 9 YAML files** following the structure from RFC-0005:
   - Copy structure from existing RFC
   - Populate with content from plan or requirements
   - Ensure schema_version and template_version are set (e.g., "2026-01-25")

3. **Key content for each file**:

   **00_meta.yaml**:
   - RFC ID, title, status (DRAFT)
   - `binds_to_prd`: Link to PRD or "NONE" for maintenance RFCs
   - `custody`: Agent roles, domains, authority signoffs
   - `implementation`: Language, edition, crate, dependencies

   **01_problem_and_imports.yaml**:
   - Clear problem statement with evidence
   - Requirements table with IDs (e.g., MAINT-006, FEAT-001)
   - Each requirement has: type, title, acceptance criteria

   **02_design_decisions.yaml**:
   - Each decision: ID, title, statement, context
   - Alternatives with pros/cons and security/operability tradeoffs
   - `chosen_rationale` explaining the decision
   - Link to `impacted_requirement_ids` and `evidence_ids`

   **03_trust_boundaries.yaml**:
   - Trust boundaries relevant to the RFC
   - May be minimal for internal tooling RFCs

   **04_contracts_and_versioning.yaml**:
   - API contracts (commands, interfaces, schemas)
   - Backward compatibility notes
   - Versioning strategy

   **05_rollout_and_ops.yaml**:
   - Rollout phases
   - Operational considerations
   - Monitoring and alerting (if applicable)

   **06_ticket_decomposition.yaml**:
   - Ticket IDs (TCK-XXXXX) with full implementation details
   - Dependencies between tickets
   - Files to modify
   - Code snippets showing before/after
   - Acceptance criteria

   **07_test_and_evidence.yaml**:
   - Test strategy (unit, integration, manual verification)
   - Test cases with inputs/expected outputs
   - Evidence requirements linking to tests

   **08_risks_and_open_questions.yaml**:
   - Risks with likelihood/impact/mitigation
   - Open questions (RESOLVED/DEFERRED status)
   - Decisions needed with options and rationale

   **09_governance_and_gates.yaml**:
   - Gate reviews (code review, security review, etc.)
   - Approval requirements

### Phase 2: Iterative Quality Review

After creating the initial RFC, spawn subagents iteratively to raise the quality bar.

**First review pass** - Focus on completeness and correctness:
```
Spawn a subagent to:
1. Read all 9 RFC files
2. Check for missing sections or incomplete content
3. Verify file paths reference actual files in the codebase
4. Ensure requirements map to tickets
5. Make improvements directly to the files
```

**Second review pass** - Focus on consistency and gaps:
```
Spawn a subagent to:
1. Check for contradictions between files
2. Verify terminology is consistent throughout
3. Ensure code snippets are syntactically correct
4. Fill gaps in test coverage documentation
5. Verify all cross-references are valid
```

**Additional passes** as needed for:
- Security considerations
- Edge case handling
- Error handling completeness
- Documentation accuracy

### Phase 3: Engineering Ticket Creation

Once the RFC is finalized, spawn parallel subagents to create engineering tickets.

**For each ticket in 06_ticket_decomposition.yaml**:

1. Create ticket file at `documents/work/tickets/TCK-XXXXX.yaml`

2. **Ticket YAML structure**:
   ```yaml
   schema_version: "2026-01-25"
   template_version: "2026-01-25"

   ticket:
     id: TCK-XXXXX
     title: "Ticket title"
     status: READY
     rfc_id: RFC-XXXX
     requirement_ids:
       - MAINT-XXX
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

3. **Spawn parallel subagents** for ticket creation:
   ```
   Spawn 9 parallel subagents, each creating one ticket:
   - Agent 1: Create TCK-00059.yaml
   - Agent 2: Create TCK-00060.yaml
   - ... (one per ticket)
   ```

   Each subagent should:
   - Read the full 06_ticket_decomposition.yaml
   - Read relevant sections from other RFC files
   - Create the complete ticket YAML
   - Ensure all fields are populated

### Phase 4: Commit, Push, and Merge

1. **Stage and commit all RFC files**:
   ```bash
   git add documents/rfcs/RFC-XXXX/ documents/skills/create-rfc/ documents/work/tickets/TCK-*.yaml
   git commit -m "docs(RFC-XXXX): add RFC title and engineering tickets"
   ```

2. **Push and create PR**:
   ```bash
   git push -u origin HEAD
   gh pr create --title "docs(RFC-XXXX): RFC Title" --body "RFC documentation and engineering tickets"
   ```

3. **Manually approve AI review statuses**:

   RFC documentation PRs do not require AI code review since they contain no executable code. Manually set the review statuses to green:
   ```bash
   # Get the HEAD SHA
   SHA=$(gh pr view <PR_NUMBER> --json headRefOid --jq '.headRefOid')

   # Set both AI review statuses to success
   gh api repos/{owner}/{repo}/statuses/$SHA -f state=success -f context=ai-review/security -f description="RFC docs - no code review needed"
   gh api repos/{owner}/{repo}/statuses/$SHA -f state=success -f context=ai-review/code-quality -f description="RFC docs - no code review needed"
   ```

4. **Merge the PR** once CI passes.

## Verification

After completing all phases:

1. **Verify RFC structure**:
   ```bash
   ls documents/rfcs/RFC-XXXX/
   # Should show all 9 files
   ```

2. **Verify tickets created**:
   ```bash
   ls documents/work/tickets/TCK-*.yaml
   # Should show all tickets referenced in RFC
   ```

3. **Cross-reference check**:
   - All requirements have at least one ticket
   - All tickets reference valid requirements
   - Dependencies form a valid DAG (no cycles)
   - File paths reference actual codebase locations

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
READY → IN_PROGRESS → COMPLETED
```

## Tips

1. **Start with existing RFCs**: Copy structure from RFC-0005 or similar
2. **Use specific file paths**: Always use actual paths from the codebase
3. **Include code snippets**: Show before/after for clarity
4. **Link everything**: Requirements → Decisions → Tickets → Tests → Evidence
5. **Be explicit about dependencies**: Ticket ordering matters for implementation
6. **Iterate on quality**: Multiple subagent passes catch different issues
