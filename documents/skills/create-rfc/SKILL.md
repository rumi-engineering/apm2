---
name: create-rfc
description: Skill for creating RFC (Request for Comments) documents with iterative quality review and ticket decomposition in the APM2 project.
user-invocable: true
holon:
  # ============================================================================
  # Contract Definition
  # ============================================================================
  # The contract defines the input/output types for this holon.
  #
  # Design Decision: DEC-RFC-3001 - Holon as Async Trait with Associated Types
  # The contract surface is specified declaratively here and enforced at runtime.
  contract:
    # Input type: RFC specification with requirements and plan references
    input_type: RfcRequest

    # Output type: Completed RFC with all 9 files and associated tickets
    output_type: RfcResult

    # State type: Tracks RFC creation progress across phases
    state_type: RfcProgress

  # ============================================================================
  # Stop Conditions
  # ============================================================================
  # Stop conditions for RFC generation work. RFC creation is a multi-phase
  # process involving document creation, iterative review, and ticket generation.
  #
  # Design Decision: DEC-RFC-3004 - Episode Stop Condition Evaluation
  # Stop conditions are evaluated after each episode in priority order.
  #
  # Security Note: These limits prevent unbounded execution during RFC creation.
  stop_conditions:
    # Maximum episodes: RFC work involves multiple phases
    #   - Phase 1: Initial RFC creation (9 files) ~ 5-10 episodes
    #   - Phase 2: Iterative quality review ~ 5-10 episodes
    #   - Phase 3: Ticket creation ~ 5-10 episodes
    #   - Phase 4: Commit and verification ~ 2-3 episodes
    # Total: 25 episodes provides headroom for complex RFCs
    max_episodes: 25

    # Timeout: 30 minutes for complete RFC generation
    # RFC creation is a longer-running process that involves extensive
    # reading, writing, and verification.
    timeout_ms: 1800000

    # Budget limits for RFC work
    budget:
      # Token budget: RFC work generates substantial text
      # - 9 RFC YAML files with detailed content
      # - Multiple ticket files
      # - Iterative review and refinement
      # 500K tokens allows for complex RFCs with multiple iterations
      tokens: 500000

      # Tool call budget: RFC work involves many file operations
      # - Reading existing RFCs for reference
      # - Creating 9+ YAML files
      # - Creating ticket files
      # - Git operations
      # 500 tool calls provides sufficient capacity
      tool_calls: 500

    # Stall detection: RFC work may have periods of exploration
    # Allow 5 episodes without progress before escalating
    max_stall_episodes: 5

  # ============================================================================
  # Tool Permissions
  # ============================================================================
  # Tools required for RFC creation work.
  #
  # Security Model (Fail-Close):
  # Only the tools explicitly listed are permitted.
  #
  # Design Decision: DEC-RFC-3003 - Lease Derivation for Sub-Holons
  # When spawning review subagents, their tool access is the intersection
  # of this parent's tools and the requested tools.
  tools:
    - Read         # Read existing RFCs, templates, and codebase files
    - Write        # Create RFC YAML files and ticket files
    - Edit         # Modify RFC files during iterative review
    - Glob         # Find files by pattern
    - Grep         # Search file contents
    - Bash         # Git operations (add, commit, push), mkdir
---

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

---

## Holon Configuration

This skill is configured to execute as a holon with bounded resource consumption.

### Stop Conditions

| Condition | Value | Description |
|-----------|-------|-------------|
| `max_episodes` | 25 | Maximum episodes across all RFC creation phases |
| `timeout_ms` | 1800000 | 30 minute wall-clock limit |
| `budget.tokens` | 500000 | Token budget for extensive document generation |
| `budget.tool_calls` | 500 | Tool call budget for file operations |
| `max_stall_episodes` | 5 | Progress stall detection threshold |

### Tool Permissions

The skill has access to tools required for RFC creation:

- `Read`: Read existing RFCs, templates, and codebase files
- `Write`: Create RFC YAML files and ticket files
- `Edit`: Modify RFC files during iterative review
- `Glob`: Find files by pattern
- `Grep`: Search file contents
- `Bash`: Git operations and directory creation

Tools not in this list are denied (fail-close security model).

### Integration with spawn_holon

This skill can be executed via the `spawn_holon` orchestration function:

```rust
use apm2_holon::spawn::{spawn_holon, SpawnConfig};
use apm2_holon::resource::{Budget, LeaseScope};
use apm2_holon::skill::parse_skill_file;

// Parse skill frontmatter
let (frontmatter, _body) = parse_skill_file("documents/skills/create-rfc/SKILL.md")?;
let holon_config = frontmatter.holon.expect("create-rfc has holon config");

// Build spawn configuration from skill config
let config = SpawnConfig::builder()
    .work_id("rfc-creation-001")
    .work_title("Create RFC-XXXX")
    .issuer_id("registrar")
    .holder_id("create-rfc")
    .scope(LeaseScope::builder()
        .tools(holon_config.allowed_tools().unwrap_or(&[]))
        .build())
    .budget(Budget::new(
        holon_config.stop_conditions.max_episodes.unwrap_or(25),
        holon_config.stop_conditions.budget.get("tool_calls").copied().unwrap_or(500),
        holon_config.stop_conditions.budget.get("tokens").copied().unwrap_or(500000),
        holon_config.stop_conditions.timeout_ms.unwrap_or(1800000),
    ))
    .build()?;

// Execute the holon
let result = spawn_holon(&mut holon, input, config, || current_time_ns())?;
```

### Related Documentation

- [RFC-0003: Holonic Framework](../../rfcs/RFC-0003/00_meta.yaml)
- [example-holon Skill](../example-holon/SKILL.md)
- [apm2-holon AGENTS.md](../../../crates/apm2-holon/AGENTS.md)

### Invariants

1. At least one stop condition is always configured (enforced at parse time)
2. Tool access follows fail-close semantics (omitted = denied)
3. Budget exhaustion triggers graceful termination, not error
4. Escalation preserves work state for supervisor continuation
5. All stop condition values must be > 0 (validated at parse time)
