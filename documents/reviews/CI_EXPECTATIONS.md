{
  "schema": "apm2.ci_expectations.v1",
  "schema_version": "1.0.0",
  "kind": "review.ci_expectations",
  "meta": {
    "stable_id": "dcp://apm2.agents/reviews/ci_expectations@1",
    "classification": "PUBLIC"
  },
  "payload": {
    "required_branch_gate": {
      "branch": "main",
      "required_check": "CI Success",
      "merge_queue": {
        "enabled": true,
        "require_merge_queue": true,
        "why": "Avoid per-PR base-branch rerun churn by validating merge-group SHAs once in queue order.",
        "workflow_trigger_requirement": {
          "event": "merge_group",
          "types": [
            "checks_requested"
          ],
          "note": "Required checks must report on merge_group commits, not only pull_request commits."
        }
      }
    },
    "checks": [
      {
        "id": "format",
        "name": "Format",
        "command": "cargo fmt --all --check",
        "validates": "Code formatting matches rustfmt standards"
      },
      {
        "id": "clippy",
        "name": "Clippy",
        "command": "cargo clippy --all-targets --all-features -- -D warnings",
        "validates": "No lint warnings or errors"
      },
      {
        "id": "test",
        "name": "Test",
        "command": "cargo test --workspace",
        "validates": "All tests pass"
      },
      {
        "id": "doc",
        "name": "Doc",
        "command": "cargo doc --no-deps",
        "validates": "Documentation builds without errors"
      },
      {
        "id": "deny",
        "name": "Deny",
        "command": "cargo deny check",
        "validates": "No banned dependencies or license violations"
      },
      {
        "id": "audit",
        "name": "Audit",
        "command": "cargo audit",
        "validates": "No known security vulnerabilities"
      }
    ]
  }
}
