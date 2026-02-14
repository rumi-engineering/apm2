# M01: Inputs and stop conditions (Fail-Closed)

```yaml
module_id: M01
domain: input_validation
inputs: [ChangeSetBundle]
outputs: [ChangeSetBundle, StopCondition[]]
```

---

## Input validation protocol

This module blocks reviews that would otherwise proceed with missing identity, missing plan-of-record, or missing baseline evidence.

```mermaid
flowchart TD
    START[Begin] --> A[Validate ChangeSet identity]
    A --> B[Validate plan-of-record binding]
    B --> C[Validate baseline CI evidence]
    C --> D{Stop condition triggered?}
    D -->|YES| E[Emit StopCondition(s) + BLOCK]
    D -->|NO| F[Emit normalized ChangeSetBundle]
```

---

## State: Validate ChangeSet identity

```yaml
required_one_of:
  - pr_url: string
  - base_sha: string
    head_sha: string

required_always:
  - diff_chunks: DiffChunk[]
  - repo_root: FilePath

assertions:
  - id: INPUT-IDENTITY-001
    predicate: "repo_root EXISTS"
    on_fail:
      EMIT StopCondition:
        id: STOP-MISSING-REPO
        severity: BLOCKER
        message: "Missing repo_root; cannot validate workspace context."
        remediation:
          type: DOC
          specification: "Provide a checked-out repo path or an extracted workspace snapshot."

  - id: INPUT-IDENTITY-002
    predicate: "diff_chunks.length > 0"
    on_fail:
      EMIT StopCondition:
        id: STOP-MISSING-DIFF
        severity: BLOCKER
        message: "Missing diff hunks; review cannot proceed."
        remediation:
          type: DOC
          specification: "Provide changed files + hunks (or a git range)."

  - id: INPUT-IDENTITY-003
    predicate: |
      IF head_sha PROVIDED THEN
        head_sha MATCHES /^[a-f0-9]{40}$/
    on_fail:
      EMIT StopCondition:
        id: STOP-INVALID-SHA
        severity: BLOCKER
        message: "Invalid head_sha."
        remediation:
          type: DOC
          specification: "Provide a 40-hex git commit SHA."
```

---

## State: Validate plan-of-record binding

```yaml
definition:
  non_trivial_change:
    # "Non-trivial" means: behavior, safety, security, policy, CI, or dependency posture.
    triggers:
      - touches_rust_code: "**/*.rs"
      - touches_policy_or_security: "documents/security/** or documents/rfcs/**"
      - touches_ci_or_guardrails: ".github/** or scripts/ci/** or deny.toml or rust-toolchain.toml"

assertions:
  - id: INPUT-BINDING-001
    predicate: |
      IF non_trivial_change THEN
        plan_of_record IS_NOT_NULL
    on_fail:
      EMIT StopCondition:
        id: STOP-NO-BINDING
        severity: BLOCKER
        message: "Non-trivial changes require a binding plan-of-record (ticket/spec/RFC) with acceptance criteria."
        remediation:
          type: DOC
          specification: "Link the change to a PRD/RFC/ticket; include acceptance criteria and security notes when relevant."
```

---

## State: Validate baseline CI evidence

This module does **not** decide QCP; it only ensures evidence exists to make review meaningful.
QCP-specific evidence requirements are evaluated later once QCP is computed (see `references/20_testing_evidence_and_ci.md`).

```yaml
baseline_ci_definition:
  acceptable_evidence:
    - "A passing run of ./scripts/ci/run_local_ci_orchestrator.sh"
    - "Equivalent CI checks with logs/artifacts attached"

  minimum_expected_signals_for_rust_changes:
    - rustfmt
    - clippy (warnings denied)
    - unit/integration tests (bounded runner if configured)
    - doc build / doctests
    - msrv check (if workspace declares rust-version)
    - dependency audit (cargo-deny and/or cargo-audit)

assertions:
  - id: INPUT-CI-001
    predicate: |
      IF diff.touches_rust_code THEN
        ci_evidence IS_NOT_NULL
    on_fail:
      EMIT StopCondition:
        id: STOP-NO-CI
        severity: BLOCKER
        message: "Rust code changed but CI evidence is missing."
        remediation:
          type: CI
          specification: "Attach CI logs/artifacts (or run the local CI orchestrator) before requesting review."

  - id: INPUT-CI-002
    predicate: |
      IF diff.touches_rust_code AND ci_evidence PROVIDED THEN
        ci_evidence.indicates_failure == false
    on_fail:
      EMIT StopCondition:
        id: STOP-CI-FAILING
        severity: BLOCKER
        message: "CI evidence indicates failing checks."
        remediation:
          type: CI
          specification: "Fix failing CI or document an approved, scoped waiver."
```

---

## Output schema

```typescript
interface StopCondition {
  id: string;
  severity: "BLOCKER";
  message: string;
  remediation: RemediationConstraint;
}

interface ChangeSetBundle {
  // intentionally abstract; actual shape is owned by the reviewing pipeline
  // and should include diff + manifests + evidence.
}
```

---

## Exit criteria

```yaml
exit_criteria:
  success:
    - stop_conditions.length == 0

  blocked:
    - stop_conditions.any(s => s.severity == "BLOCKER")
```
