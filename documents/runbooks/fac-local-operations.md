# FAC Local Operations Runbook

Operational procedures for running the Forge Admission Cycle (FAC) evidence
gates locally using the `apm2 fac gates` command.

**Audience:** New operators bootstrapping FAC on a single host.
**Prerequisites:** Ubuntu 24.04, systemd user session, cgroup v2.
**Authority:** RFC-0019 Amendment A1 (FESv1), RFC-0007 (build tooling).

---

## 1. Bootstrap: first-time setup

### 1.1 Install required tools

```bash
# Rust toolchain (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# mold linker (faster linking)
sudo apt install mold clang

# cargo-nextest (recommended for FAC bounded test gate)
cargo install cargo-nextest

# Verify installations
which mold         # /usr/bin/mold
cargo nextest --version
```

**nextest is the preferred and recommended test runner.** When the bounded
test runner is available (cgroup v2 + `run_bounded_tests.sh`), FAC uses
`cargo nextest run` inside a resource-bounded cgroup unit. When the bounded
runner inputs are absent, the current implementation falls back to
`cargo test --workspace`. Fail-closed enforcement (rejecting execution when
nextest is unavailable) is planned for a future ticket (see DD-003 in
RFC-0007 for the design intent).

### 1.2 Enable systemd user session (required for bounded execution)

FAC uses `systemd-run --user` to enforce resource limits (memory, CPU, PIDs,
wall-time) on evidence gate execution. This requires a functioning user bus.

```bash
# Enable lingering for your user (persists across SSH sessions)
sudo loginctl enable-linger $(whoami)

# Verify user bus is available
systemctl --user status
# Expected: shows active user session manager

# If the above fails, ensure XDG_RUNTIME_DIR is set
echo $XDG_RUNTIME_DIR
# Expected: /run/user/$(id -u)
```

**If bounded execution is unavailable** (the bounded runner script is missing
or cgroup v2 is unavailable), `apm2 fac gates` falls back to running evidence
gates without cgroup resource limits. The bounded execution path is strongly
recommended. Fail-closed enforcement when bounded execution is unavailable is
planned as future work (see DD-003 in RFC-0007).
When the bounded runner script is present but the user bus is unavailable,
bounded execution does not fall back. It hard-fails in `run_bounded_tests.sh`
preflight. Fix the user session to enable bounded execution before proceeding.

### 1.3 Build and install the apm2 CLI

```bash
cd /path/to/apm2
cargo build --release -p apm2-cli
# Add to PATH or create alias
```

### 1.4 Initialize FAC directory structure

The FAC substrate creates its directory structure under `$APM2_HOME`
(defaults to `~/.apm2`) on first use. The current layout is:

```
$APM2_HOME/private/fac/
  evidence/           # Per-gate evidence logs (written by apm2 fac gates)
  gate_cache_v2/      # Gate cache for SHA-based result reuse
```

> **PLANNED — not yet implemented.** The FESv1 execution substrate will
> introduce additional directories when the queue/worker surface is
> implemented in a future ticket:
>
> ```
> $APM2_HOME/private/fac/
>   lanes/              # Execution lanes (bounded workspaces)
>   queue/              # Job queue (filesystem-backed)
>   receipts/           # Content-addressed receipt objects
>   locks/              # Lane and queue locks
>   repo_mirror/        # Node-local bare git mirror
>   cargo_home/         # FAC-managed CARGO_HOME (isolated from ~/.cargo)
>   broker/             # Broker state (policy roots, horizons)
>   scheduler/          # Scheduler state persistence
> ```

---

## 2. PLANNED — FESv1 lane bootstrap (not yet implemented)

> **This entire section describes PLANNED behavior.** The FESv1 lane/queue
> execution substrate is not yet implemented. Current FAC operation uses
> `apm2 fac gates` for local in-process gate execution (see section 3.1).
> The concepts below will apply when the FESv1 queue/worker surface is
> implemented in a future ticket.

### 2.1 Understanding lanes (PLANNED)

A **lane** is a bounded, cullable execution context with:
- A dedicated workspace (clean git checkout from the node-local bare mirror)
- A dedicated target directory (compilation cache per toolchain fingerprint)
- A dedicated log directory (per-job namespacing)
- A fixed resource profile enforced via systemd cgroups

Lane lifecycle: `IDLE -> LEASED -> RUNNING -> CLEANUP -> IDLE`
Exceptional: `* -> CORRUPT -> RESET -> IDLE`

The default lane count is 3 (derived from host memory policy: 96 GB / 24 GB
per lane = 3 concurrent lanes, with headroom for OS and non-FAC processes).

### 2.2 Check lane status (PLANNED)

> **PLANNED -- not yet implemented.** The `apm2 fac lane` subcommand does not
> exist in the current CLI. Lane status inspection is planned for a future
> ticket implementing the FESv1 lane management surface.

### 2.3 Pre-warm lane targets (PLANNED)

> **PLANNED -- not yet implemented.** The `apm2 fac warm` subcommand does not
> exist in the current CLI. Lane pre-warming is planned for a future ticket
> implementing the FESv1 lane management surface.

---

## 3. Start services

### 3.1 Running gates (local execution)

The `apm2 fac gates` command executes evidence gates locally in-process:

1. Checks for a clean working tree (full mode) or skips the check (`--quick`)
2. Resolves the HEAD SHA
3. Runs the merge-conflict gate first (always recomputed)
4. Runs evidence gates (with bounded test runner if `cargo-nextest` is available)
5. Writes attested gate cache receipts for full runs
6. Prints a summary table with verdict (PASS / FAIL)

```bash
# Run all evidence gates locally
apm2 fac gates

# Quick mode for development iteration (skips test gate, accepts dirty tree)
apm2 fac gates --quick
```

> **PLANNED -- not yet implemented.** Queue-based execution (creating a
> `FacJobSpecV1` job spec, obtaining an RFC-0028 channel context token from
> the broker, enqueueing to `queue/pending/`, and waiting for a worker to
> claim and execute) is planned for a future ticket implementing the FESv1
> queue/worker surface. The current CLI runs all gates locally.

### 3.2 Running a worker (PLANNED)

> **PLANNED -- not yet implemented.** The `apm2 fac worker` subcommand does not
> exist in the current CLI. Standalone worker execution is planned for a future
> ticket implementing the FESv1 queue/worker surface. The apm2-daemon service
> does not currently include worker functionality; this will be added when the
> FESv1 queue/worker surface is implemented.

### 3.3 Running GC (garbage collection)

> **PLANNED -- not yet implemented.** The `apm2 fac gc` subcommand does not
> exist in the current CLI. Automated garbage collection is planned for a
> future ticket. For now, reclaim disk space manually:

```bash
# Remove old evidence logs
rm -rf "${APM2_HOME:-$HOME/.apm2}/private/fac/evidence/"

# Check disk usage
du -sh "${APM2_HOME:-$HOME/.apm2}/private/fac/evidence/" 2>/dev/null
```

Run manual cleanup when:
- Disk usage exceeds comfortable thresholds
- Before large batch operations
- Periodically via cron/systemd timer

### 3.4 Enqueueing jobs manually (PLANNED)

> **PLANNED -- not yet implemented.** The `apm2 fac enqueue` subcommand does
> not exist in the current CLI. Manual job enqueueing is planned for a future
> ticket implementing the FESv1 queue/worker surface. For now, use `apm2 fac gates`
> for local gate execution.

---

## 4. PLANNED — Respond to quarantine and denials (not yet implemented)

> **PLANNED -- not yet implemented.** This entire section describes planned
> behavior for the FESv1 queue/worker surface, which is not yet implemented.
> The current `apm2 fac gates` command executes gates locally and does not
> produce quarantine or denial artifacts. The procedures below describe the
> planned queue-based behavior.

### 4.1 Understanding quarantine (PLANNED)

When queue-based execution is implemented, a job will be moved to
`queue/quarantine/` when it fails validation:

- **RFC-0028 channel boundary check failed:** The job's `channel_context_token`
  did not pass `decode_channel_context_token` + `validate_channel_boundary`.
  This means the job was not properly authorized by the broker.
- **Malformed job spec:** The `FacJobSpecV1` could not be parsed with
  bounded deserialization.
- **Integrity check failed:** The `job_spec_digest` does not match the
  computed digest of the job spec contents.

**Quarantined items are preserved for forensics. Never delete them manually.**

### 4.2 Diagnosing quarantined jobs (PLANNED)

```bash
# List quarantined items
ls "${APM2_HOME:-$HOME/.apm2}/private/fac/queue/quarantine/"

# Inspect a quarantined job (the original spec is preserved)
cat "${APM2_HOME:-$HOME/.apm2}/private/fac/queue/quarantine/<job_id>.json"

# Check for associated denial receipt
ls "${APM2_HOME:-$HOME/.apm2}/private/fac/receipts/" | grep <job_id>
```

Common causes and remediation:

| Symptom | Cause | Fix |
|---------|-------|-----|
| Token decode failure | Broker signing key rotated | Restart broker, re-enqueue job |
| Policy binding mismatch | Policy root changed between enqueue and claim | Re-enqueue with current policy root |
| Malformed spec | Corrupted file or incompatible schema version | Regenerate job spec |
| Digest mismatch | File modified after creation (possible A2 attack) | Investigate, re-enqueue from trusted source |

### 4.3 Understanding denials (PLANNED)

When queue-based execution is implemented, a job will be moved to
`queue/denied/` when it fails RFC-0029 queue admission:

- **Budget exceeded:** The job's resource cost exceeds available budget
- **Lane capacity:** No lanes available within the admission window
- **Anti-starvation:** Higher-priority queue lanes are draining first

```bash
# List denied items
ls "${APM2_HOME:-$HOME/.apm2}/private/fac/queue/denied/"

# Inspect denial reason (sidecar file)
cat "${APM2_HOME:-$HOME/.apm2}/private/fac/queue/denied/<job_id>.reason.json"
```

### 4.4 Recovering from quarantine/denial (PLANNED)

```bash
# After fixing the root cause, re-run gates locally:
apm2 fac gates
```

---

## 5. PLANNED — Safe lane reset (not yet implemented)

> **PLANNED -- not yet implemented.** This entire section describes planned
> behavior for the FESv1 lane management surface. Lanes do not exist in the
> current implementation. The current `apm2 fac gates` command executes
> gates locally in-process and does not use lanes.

### 5.1 When to reset a lane (PLANNED)

Reset a lane when it enters CORRUPT state or when you need to recover
from a failed cleanup. Common triggers:

- Lane cleanup failed (e.g., permission error, disk full during cleanup)
- Process outlived its lease (cgroup kill timed out)
- Symlink safety check refused deletion (suspicious filesystem state)
- Lane workspace contaminated (unknown files from escaped process)

### 5.2 Check lane state before reset (PLANNED)

```bash
# PLANNED: apm2 fac lane status
# Lane state inspection commands will be available when FESv1 is implemented
```

### 5.3 Perform safe lane reset (PLANNED)

When the `apm2 fac lane reset` command is implemented, it will provide
these safety guarantees:
1. Symlink-safe recursive deletion (verifies each path component)
2. Refuses to cross filesystem boundaries
3. Refuses to delete unexpected file types (device nodes, sockets)
4. Writes a reset receipt with lane state before and after

---

## 6. Troubleshooting

### 6.1 Gates fail to start

```
Symptom: apm2 fac gates hangs or returns immediately with no output
```

1. Check process health: `systemctl --user status apm2-daemon`
2. Check evidence logs: `ls "${APM2_HOME:-$HOME/.apm2}/private/fac/evidence/"` and `apm2 fac --json logs`
3. Check disk space: `df -h` and `du -sh "${APM2_HOME:-$HOME/.apm2}/private/fac/"`

### 6.2 Cold-start timeout (240s exceeded)

```
Symptom: Test gate fails with timeout during large compilation
```

1. Pre-warm the build by running `cargo build --workspace` before running gates
2. If warming itself times out, check if dependencies changed significantly
3. Consider freeing disk space manually (see section 3.3)

### 6.3 bounded test execution unavailable

```
Symptom: Test gate falls back to `cargo test --workspace` instead of bounded
         `cargo nextest run`
```

Fix: Ensure the bounded runner can start. The fallback to `cargo test
--workspace` is expected only when `run_bounded_tests.sh` is missing or
cgroup v2 is unavailable.

nextest remains the preferred and recommended test runner for FAC evidence
gates (DD-003, RFC-0007). If bounded execution is available but
`cargo nextest` is not installed, FAC gates fail closed (test-gate
failure). Install nextest to enable bounded execution with resource limits.
Fail-closed enforcement for missing nextest in unbounded mode is planned as
future work.

### 6.4 systemd-run fails (no user bus)

```
Symptom: "Failed to connect to user bus" or similar systemd error
```

1. Enable lingering: `sudo loginctl enable-linger $(whoami)`
2. Verify: `systemctl --user status`
3. Ensure XDG_RUNTIME_DIR is set: `echo $XDG_RUNTIME_DIR`
4. For SSH sessions, ensure `pam_systemd` is configured

### 6.5 Disk exhaustion

```
Symptom: Builds fail with "No space left on device"
```

1. Free disk space manually (see section 3.3)
2. Check for orphaned evidence logs: `du -sh "${APM2_HOME:-$HOME/.apm2}/private/fac/evidence/"`
3. Check build target directories: `du -sh target/`
4. Target directories are compilation caches (safe to delete): `rm -rf target/`

### 6.6 Stale lease (PLANNED — FESv1 future)

> **PLANNED -- not yet implemented.** Stale lease detection and recovery
> applies to the FESv1 lane management surface. The current `apm2 fac gates`
> command does not use lanes or leases.

### 6.7 Containment violation (PLANNED — FESv1 future)

> **PLANNED -- not yet implemented.** Containment violation detection applies
> to the FESv1 lane management surface. The current `apm2 fac gates` command
> executes gates locally without cgroup-based lane isolation.
>
> When FESv1 is implemented, check for:
> 1. sccache daemon leaking outside cgroup boundary
> 2. RUSTC_WRAPPER overrides in FAC execution environment
> 3. Ambient ~/.cargo/config.toml overriding FAC policy

---

## 7. Reference: CLI commands

### Currently implemented

| Command | Purpose |
|---------|---------|
| `apm2 fac gates` | Run evidence gates locally (default) |
| `apm2 fac doctor` | Check daemon health and prerequisites |
| `apm2 fac gates --quick` | Quick validation (skips tests, accepts dirty tree) |
| `apm2 fac push --ticket <yaml>` | Push and create/update PR |
| `apm2 fac --json logs` | Show log file paths |
| `apm2 fac --json logs --pr <N>` | Show logs for a specific PR |
| `apm2 fac review` | Run and observe FAC review orchestration |
| `apm2 fac restart` | Restart evidence/review pipeline |
| `apm2 fac work` | Query projection-backed work authority |
| `apm2 fac receipt` | Show receipt from CAS |
| `apm2 fac episode` | Inspect episode details and tool log index |
| `apm2 fac context` | Rebuild role-scoped context deterministically |
| `apm2 fac resume` | Show crash-only resume helpers from ledger anchor |
| `apm2 fac role-launch` | Launch a FAC role with hash-bound admission checks |
| `apm2 fac pr` | GitHub App credential management and PR operations |

### PLANNED -- not yet implemented (FESv1 queue/worker/lane surface)

| Command | Purpose |
|---------|---------|
| `apm2 fac lane status` | Show all lane states |
| `apm2 fac lane reset <id>` | Reset a lane to known-good state |
| `apm2 fac lane reset <id> --force` | Force-reset a running lane |
| `apm2 fac warm` | Pre-warm all lane targets |
| `apm2 fac warm --lane <id>` | Pre-warm a specific lane |
| `apm2 fac gc` | Reclaim disk space across all FAC roots |
| `apm2 fac gc --lane <id>` | Reclaim disk space for a specific lane |
| `apm2 fac worker --once` | Run one job claim/execute cycle |
| `apm2 fac worker` | Run worker continuously |
| `apm2 fac enqueue <spec>` | Enqueue a job from a spec file |
| `apm2 fac enqueue --cancel <id>` | Cancel a pending job |

---

## 8. PLANNED — Reference: lane lifecycle state machine (FESv1 future)

```
                    +---------+
           +------->|  IDLE   |<--------+
           |        +---------+         |
           |            |               |
           |      (lease acquired)      |
           |            v               |
           |        +---------+         |
           |        | LEASED  |         |
           |        +---------+         |
           |            |               |
           |      (job execution)       |
           |            v               |
           |        +---------+         |
           |        | RUNNING |    (cleanup ok)
           |        +---------+         |
           |            |               |
           |      (job completes)       |
           |            v               |
           |        +---------+         |
           +--------| CLEANUP |---------+
                    +---------+
                        |
                  (cleanup fails)
                        v
                    +---------+       +---------+
                    | CORRUPT |------>|  RESET  |-----> IDLE
                    +---------+       +---------+
                        ^
                        |
                  (any failure)
```

---

## 9. PLANNED — Reference: queue lane priority order (FESv1 future)

> **PLANNED -- not yet implemented.** Queue lanes are part of the FESv1
> queue/worker surface and do not exist in the current implementation.

When implemented, queue lanes will determine scheduling priority (highest first):

1. `stop_revoke` - Stop/revocation commands (highest priority)
2. `control` - Control plane operations
3. `consume` - Consumption operations
4. `replay` - Replay operations
5. `projection_replay` - Projection replay operations
6. `bulk` - Bulk operations (lowest priority, default for gates)

Within a queue lane, `priority` (descending) will win. Ties will break by
`enqueue_time` (oldest first), then `job_id` (lexicographic).
