# FAC Local Gate Runbook (TCK-00410)

## Purpose
Operate FAC-local CI gate execution on OVH self-hosted runners while keeping GitHub as projection-only status surface and preserving required `CI Success` merge-gate semantics.

## Required Runner Profile
- Labels: `self-hosted`, `linux`, `x64`, `fac-ovh`
- Host requirements:
  - Linux with cgroup v2 mounted at `/sys/fs/cgroup`
  - `systemd-run` available for transient bounded scopes
  - Rust toolchain baseline `nightly-2025-12-01`
  - `cargo-nextest`, `protoc`, and GitHub Actions runner service installed

## Blocking Guard Jobs
- `Test Safety Guard`
  - Command: `./scripts/ci/test_safety_guard.sh`
  - Blocks destructive test signatures pre-execution.
- `Bounded Test Runner`
  - Command: `./scripts/ci/run_bounded_tests.sh`
  - Enforces timeout + cgroup/systemd ceilings (CPU/memory/pids).
- `Workspace Integrity Guard`
  - Command: `./scripts/ci/workspace_integrity_guard.sh -- <bounded test command>`
  - Fails if tracked repository content mutates unexpectedly after tests.

## Failure-Injection Validation
- Command: `./scripts/ci/test_guardrail_fixtures.sh`
- Verifies:
  - dangerous test signatures are rejected
  - tracked workspace mutation is detected
  - hung commands are terminated by watchdog limits

## Operational Procedure
1. Confirm runner is online with `fac-ovh` label in GitHub Actions.
2. Trigger CI on PR and merge-group SHA.
3. Verify `CI Success` includes:
   - `Test Safety Guard`
   - `Bounded Test Runner`
   - `Workspace Integrity Guard`
4. On failures, inspect job logs and corresponding guard script output.
5. If test-safety false positives occur, add minimal scoped entries to `scripts/ci/test_safety_allowlist.txt`.

## Triage Notes
- `systemd-run` authentication errors:
  - Ensure runner service account can create transient units (`systemd-run --user` or system scope policy).
- Missing cgroup controllers:
  - Validate cgroup v2 mount and controller availability (`cat /sys/fs/cgroup/cgroup.controllers`).
- Workspace drift failures:
  - Use `git diff --name-only` to inspect unexpected tracked file mutation after tests.
