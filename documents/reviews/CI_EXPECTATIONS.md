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
    "execution_model": {
      "github_surface": "single required workflow job `CI Success` on runner labels [self-hosted, linux, x64, fac-ovh]",
      "local_executor": "cargo run --locked --package apm2-cli -- ci run --profile <github-pr-fast|github-deep|github-slow-lane> --bounded-timeout-seconds 4800 --bounded-kill-after-seconds 30 --bounded-memory-max 64G --bounded-pids-max 8192 --bounded-cpu-quota 1600% --heartbeat-seconds 1 --heavy-lane-tokens 4 --log-mode dual --artifacts-dir target/ci/runs",
      "note": "The CI suite is orchestrated by `apm2 ci` in Rust (no shell orchestration), executed once inside a transient user unit/cgroup boundary, drains lingering child processes before unit exit, and emits structured artifacts at target/ci/runs/. `CI Success` uses fast/deep profiles; release build moved to `github-slow-lane` in a separate non-required workflow."
    },
    "profiles": {
      "github-pr-fast": {
        "event_scope": ["pull_request"],
        "budget_target_seconds": 120,
        "intent": "Fast PR gate for high-concurrency iteration while preserving bounded execution and core guardrails.",
        "surface_note": "Fast profile intentionally omits duplicate compile/proto-heavy stages to keep warm-cache runtimes near the 2-minute target."
      },
      "github-deep": {
        "event_scope": ["push", "merge_group"],
        "budget_target_seconds": 5400,
        "intent": "Deep validation surface on mainline and merge-group SHAs (excluding release build)."
      },
      "github-slow-lane": {
        "event_scope": ["push", "workflow_dispatch"],
        "budget_target_seconds": 10800,
        "intent": "Slow-lane heavyweight checks outside required CI Success gate."
      }
    },
    "checks": [
      {
        "id": "rustfmt",
        "name": "Rustfmt",
        "command": "cargo fmt --all --check",
        "validates": "Code formatting matches rustfmt standards"
      },
      {
        "id": "proto-verify",
        "name": "Proto Verify",
        "command": "cargo build -p apm2-daemon && git diff --exit-code crates/apm2-daemon/src/protocol/apm2.daemon.v1.rs",
        "validates": "Checked-in generated proto code matches proto definitions"
      },
      {
        "id": "clippy",
        "name": "Clippy",
        "command": "cargo clippy --workspace --all-targets --all-features -- -D warnings",
        "validates": "No lint warnings or errors"
      },
      {
        "id": "doc",
        "name": "Documentation",
        "command": "RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --all-features",
        "validates": "Documentation builds without errors"
      },
      {
        "id": "workspace-integrity-snapshot",
        "name": "Workspace Integrity Snapshot",
        "command": "./scripts/ci/workspace_integrity_guard.sh snapshot --snapshot-file target/ci/workspace_integrity.snapshot.tsv",
        "validates": "Baseline tracked workspace state is captured before test execution"
      },
      {
        "id": "bounded-test-runner",
        "name": "Bounded Test Runner",
        "command": "cargo nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci",
        "validates": "Workspace tests execute once inside the bounded local CI suite"
      },
      {
        "id": "workspace-integrity-guard",
        "name": "Workspace Integrity Guard",
        "command": "./scripts/ci/workspace_integrity_guard.sh verify --snapshot-file target/ci/workspace_integrity.snapshot.tsv",
        "validates": "Tracked repository state remains unchanged after the single bounded test run"
      },
      {
        "id": "bounded-doctests",
        "name": "Bounded Doctests",
        "command": "cargo test --doc --workspace --all-features",
        "validates": "Workspace doctests execute in the bounded local CI suite"
      },
      {
        "id": "test-vectors",
        "name": "Test Vectors",
        "command": "cargo test --package apm2-core --features test_vectors canonicalization",
        "validates": "Canonicalization vectors remain valid"
      },
      {
        "id": "msrv",
        "name": "MSRV (1.85)",
        "command": "cargo +1.85 check --workspace --all-features",
        "validates": "Workspace builds on MSRV"
      },
      {
        "id": "security-audit",
        "name": "Security Audit",
        "command": "cargo audit --ignore RUSTSEC-2023-0089",
        "validates": "No known security vulnerabilities (excluding configured ignore)"
      },
      {
        "id": "deny",
        "name": "Cargo Deny",
        "command": "cargo deny check all",
        "validates": "No banned dependencies or license violations"
      },
      {
        "id": "coverage",
        "name": "Coverage",
        "command": "cargo llvm-cov --workspace --all-features --lcov --output-path target/ci/lcov.info",
        "validates": "Coverage instrumentation/tests run and emit lcov artifact"
      },
      {
        "id": "build",
        "name": "Release Build",
        "command": "cargo build --workspace --release",
        "validates": "Release profile build succeeds (github-slow-lane profile)"
      },
      {
        "id": "safety-proof-coverage",
        "name": "Safety Proof Coverage",
        "command": "./scripts/ci/safety_proof_coverage.sh",
        "validates": "Unsafe blocks are documented with SAFETY comments"
      },
      {
        "id": "legacy-ipc-guard",
        "name": "Legacy IPC Guard",
        "command": "./scripts/ci/legacy_ipc_guard.sh",
        "validates": "Legacy JSON IPC patterns remain blocked"
      },
      {
        "id": "evidence-refs-lint",
        "name": "Evidence Refs Lint",
        "command": "./scripts/ci/evidence_refs_lint.sh",
        "validates": "Evidence and requirement references are consistent"
      },
      {
        "id": "test-refs-lint",
        "name": "Test Refs Lint",
        "command": "./scripts/ci/test_refs_lint.sh",
        "validates": "Evidence source_refs point to existing files"
      },
      {
        "id": "proto-enum-drift",
        "name": "Proto Enum Drift",
        "command": "./scripts/ci/proto_enum_drift.sh",
        "validates": "Proto enum definitions and generated Rust code remain aligned"
      },
      {
        "id": "review-artifact-lint",
        "name": "Review Artifact Lint",
        "command": "./scripts/ci/review_artifact_lint.sh",
        "validates": "Review artifacts preserve SHA and policy integrity"
      },
      {
        "id": "status-write-command-lint",
        "name": "Status Write Command Lint",
        "command": "./scripts/lint/no_direct_status_write_commands.sh",
        "validates": "Direct status-write command drift is blocked"
      },
      {
        "id": "test-safety-guard",
        "name": "Test Safety Guard",
        "command": "./scripts/ci/test_safety_guard.sh",
        "validates": "Dangerous test patterns are blocked"
      },
      {
        "id": "guardrail-fixtures",
        "name": "Guardrail Fixtures",
        "command": "./scripts/ci/test_guardrail_fixtures.sh",
        "validates": "Guardrail failure-injection fixtures pass"
      }
    ]
  }
}
