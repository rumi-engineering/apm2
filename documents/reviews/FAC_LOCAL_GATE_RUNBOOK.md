# FAC Local Gate Runbook (TCK-00410)

## Purpose
Operate FAC-local CI gate execution on OVH self-hosted runners while keeping GitHub as projection-only status surface and preserving required `CI Success` merge-gate semantics.

## Required Runner Profile
- Labels: `self-hosted`, `linux`, `x64`, `fac-ovh`
- Machine identity mapping:
  - `fac-ovh` means this specific host: `rust-forge-01`.
  - Registered runner service on this host: `actions.runner.guardian-intelligence-apm2.ubuntu-ovh-runner.service`.
  - This runbook assumes CI compute happens on this machine and GitHub only receives projected status.
- Host requirements:
  - Linux with cgroup v2 mounted at `/sys/fs/cgroup`
  - `systemd-run` available for transient bounded scopes
  - Rust toolchain baseline `nightly-2025-12-01`
  - `cargo-nextest`, `cargo-deny`, `cargo-audit`, `cargo-llvm-cov`, `protoc`, `rg`, `jq`, and GitHub Actions runner service installed
  - Parallel job execution requires multiple runner agents registered on this machine with the same labels (one runner process executes one job at a time).

## Blocking Guard Checks
- `Bounded CI Suite`
  - Command (deep profile): `cargo run --locked --package apm2-cli -- ci run --profile github-deep --bounded-timeout-seconds 4800 --bounded-kill-after-seconds 30 --bounded-memory-max 64G --bounded-pids-max 8192 --bounded-cpu-quota 1600% --heartbeat-seconds 1 --heavy-lane-tokens 4 --log-mode dual --artifacts-dir target/ci/runs`
  - Command (fast PR profile): `cargo run --locked --package apm2-cli -- ci run --profile github-pr-fast --bounded-timeout-seconds 4800 --bounded-kill-after-seconds 30 --bounded-memory-max 64G --bounded-pids-max 8192 --bounded-cpu-quota 1600% --heartbeat-seconds 1 --heavy-lane-tokens 4 --log-mode dual --artifacts-dir target/ci/runs`
  - Command (slow-lane profile): `cargo run --locked --package apm2-cli -- ci run --profile github-slow-lane --bounded-timeout-seconds 4800 --bounded-kill-after-seconds 30 --bounded-memory-max 64G --bounded-pids-max 8192 --bounded-cpu-quota 1600% --heartbeat-seconds 1 --heavy-lane-tokens 4 --log-mode dual --artifacts-dir target/ci/runs`
  - `apm2 ci run` wraps the suite once in a transient user unit/cgroup boundary; no shell orchestrator is used.
- Deep profile check surface, executed inside orchestrator:
  - `rustfmt`, `proto-verify`, `clippy`, `doc`
  - `workspace-integrity-snapshot`, `bounded-test-runner`, `workspace-integrity-guard`, `bounded-doctests`, `test-vectors`
  - `msrv`, `cargo-deny`, `cargo-audit`, `coverage`
  - `safety-proof-coverage`, `legacy-ipc-guard`, `evidence-refs-lint`, `test-refs-lint`, `proto-enum-drift`, `review-artifact-lint`, `status-write-command-lint`, `test-safety-guard`, `guardrail-fixtures`
  - `workspace-integrity-guard` verifies the snapshot after the single `bounded-test-runner` execution (no duplicate `nextest` run).
- Fast profile check surface (PR):
  - `rustfmt`
  - `workspace-integrity-snapshot`, `bounded-test-runner`, `workspace-integrity-guard`
  - `safety-proof-coverage`, `legacy-ipc-guard`, `evidence-refs-lint`, `test-refs-lint`, `proto-enum-drift`, `review-artifact-lint`, `status-write-command-lint`, `test-safety-guard`, `guardrail-fixtures`
  - Proto regeneration and heavyweight compile/lint/doc/coverage stages are reserved for `github-deep` to avoid duplicate compile passes in PR fast gates.
- Slow-lane profile check surface (non-gating):
  - `release-build`
  - Triggered by `.github/workflows/ci-slow-lane.yml` and excluded from required `CI Success`.

## Operational Procedure
1. Confirm `fac-ovh` resolves to this host and runner service:
   - `hostnamectl --static` must return `rust-forge-01`.
   - `systemctl status actions.runner.guardian-intelligence-apm2.ubuntu-ovh-runner.service` must be `active (running)`.
2. Confirm runner is online in GitHub Actions with label set: `self-hosted`, `linux`, `x64`, `fac-ovh`.
3. Trigger CI on PR and merge-group SHA.
4. Verify `CI Success` job logs show:
   - `Preflight passed: systemd-run --user is functional`
   - `Starting bounded command in transient user unit`
   - periodic `HEALTH:` heartbeat lines (default every 1s)
   - `=== CI Summary ===` and PASS/FAIL rows for the profile's check surface
   - if tests leak child processes, bounded teardown logs `detected lingering bounded-unit processes; attempting drain` followed by completion status
   - run artifacts emitted under `target/ci/runs/<run_id>/` (manifest, events.ndjson, per-task logs, summary.json)
   - If deep profile coverage runs, `target/ci/lcov.info` exists and Codecov upload step executes (non-blocking).
5. On failures, inspect summary output and the matching `target/ci/runs/<run_id>/tasks/<task_id>.log` entries.
6. If test-safety false positives occur, add minimal scoped entries to `scripts/ci/test_safety_allowlist.txt`.

## Triage Notes
- `systemd-run` authentication errors:
  - Ensure `systemd-run --user` is functional for the runner account.
  - Verify linger and user manager: `loginctl show-user ubuntu` includes `Linger=yes`, and `systemctl status user@1000.service` is active.
  - Verify runner service exports user-bus environment:
    - `XDG_RUNTIME_DIR=/run/user/1000`
    - `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus`
- Missing cgroup controllers:
  - Validate cgroup v2 mount and controller availability (`cat /sys/fs/cgroup/cgroup.controllers`).
- Workspace drift failures:
  - Use `git diff --name-only` to inspect unexpected tracked file mutation after tests.
