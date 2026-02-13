# FAC Local Operations Runbook

Operational procedures for running the Forge Admission Cycle (FAC) evidence
gates locally using the FESv1 execution substrate (broker, worker, lanes).

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

**If bounded execution is unavailable** (no user bus, no cgroup v2), `apm2 fac gates`
falls back to running evidence gates without cgroup resource limits. The bounded
execution path is strongly recommended. Fail-closed enforcement when bounded
execution is unavailable is planned as future work (see DD-003 in RFC-0007).
Fix the user session to enable bounded execution before proceeding.

### 1.3 Build and install the apm2 CLI

```bash
cd /path/to/apm2
cargo build --release -p apm2-cli
# Add to PATH or create alias
```

### 1.4 Initialize FAC directory structure

The FAC substrate creates its directory structure under `$APM2_HOME`
(defaults to `~/.apm2`) on first use. The layout is:

```
$APM2_HOME/private/fac/
  lanes/              # Execution lanes (bounded workspaces)
    lane-0/
      workspace/      # Clean git checkout for this lane
      target/         # Lane-scoped compilation cache (per toolchain)
      logs/           # Per-job log namespaces
      lease.v1.json   # Current lease record
    lane-1/
    lane-2/
  queue/              # Job queue (filesystem-backed)
    pending/          # Jobs waiting for execution
    claimed/          # Jobs currently being executed
    done/             # Completed jobs with receipts
    cancelled/        # Cancelled jobs
    denied/           # Jobs denied by RFC-0029 admission
    quarantine/       # Malformed/tampered jobs (forensic preservation)
  receipts/           # Content-addressed receipt objects
  locks/              # Lane and queue locks
  repo_mirror/        # Node-local bare git mirror
  cargo_home/         # FAC-managed CARGO_HOME (isolated from ~/.cargo)
  broker/             # Broker state (policy roots, horizons)
  scheduler/          # Scheduler state persistence
  evidence/           # Legacy global per-gate logs (deprecated)
  gate_cache_v2/      # Legacy gate cache (migration target)
```

---

## 2. Bootstrap lanes

### 2.1 Understanding lanes

A **lane** is a bounded, cullable execution context with:
- A dedicated workspace (clean git checkout from the node-local bare mirror)
- A dedicated target directory (compilation cache per toolchain fingerprint)
- A dedicated log directory (per-job namespacing)
- A fixed resource profile enforced via systemd cgroups

Lane lifecycle: `IDLE -> LEASED -> RUNNING -> CLEANUP -> IDLE`
Exceptional: `* -> CORRUPT -> RESET -> IDLE`

The default lane count is 3 (derived from host memory policy: 96 GB / 24 GB
per lane = 3 concurrent lanes, with headroom for OS and non-FAC processes).

### 2.2 Check lane status

> **PLANNED -- not yet implemented.** The `apm2 fac lane` subcommand does not
> exist in the current CLI. Lane status inspection is planned for a future
> ticket implementing the FESv1 lane management surface. For now, inspect
> lane state by examining the filesystem directly:

```bash
# Check lane lease files
ls $APM2_HOME/private/fac/lanes/*/lease.v1.json 2>/dev/null

# Check lane workspace directories
ls -la $APM2_HOME/private/fac/lanes/
```

Expected directory layout (healthy state — no active leases):

```
$APM2_HOME/private/fac/lanes/
  lane-0/
    workspace/
    target/
    logs/
  lane-1/
  lane-2/
```

### 2.3 Pre-warm lane targets (reduce cold-start probability)

Cold-start compilation (building all dependencies from scratch) can exceed
the 240-second wall-time limit for the test gate. Pre-warming populates
each lane's target directory with compiled dependencies.

> **PLANNED -- not yet implemented.** The `apm2 fac warm` subcommand does not
> exist in the current CLI. Lane pre-warming is planned for a future ticket
> implementing the FESv1 lane management surface. For now, pre-warm manually:

```bash
# Pre-warm a lane's target directory by running a build in the lane workspace
cd $APM2_HOME/private/fac/lanes/lane-0/workspace
CARGO_TARGET_DIR=$APM2_HOME/private/fac/lanes/lane-0/target cargo build --workspace
```

After warming, gate execution avoids full dependency recompilation.

**When to warm:**
- After initial bootstrap (lanes have empty target directories)
- After a toolchain update (rustc version change invalidates targets)
- After a lane reset (target directory is deleted)
- After major dependency changes in Cargo.toml/Cargo.lock

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

### 3.2 Running a worker

> **PLANNED -- not yet implemented.** The `apm2 fac worker` subcommand does not
> exist in the current CLI. Standalone worker execution is planned for a future
> ticket implementing the FESv1 queue/worker surface.

For production operation, use the apm2-daemon service which includes worker
functionality:

```bash
# The apm2-daemon service includes worker functionality
# Check if the service is running:
systemctl --user status apm2-daemon

# Start if not running:
systemctl --user start apm2-daemon

# Enable auto-start on login:
systemctl --user enable apm2-daemon
```

### 3.3 Running GC (garbage collection)

> **PLANNED -- not yet implemented.** The `apm2 fac gc` subcommand does not
> exist in the current CLI. Automated garbage collection is planned for a
> future ticket implementing the FESv1 lane management surface. For now,
> reclaim disk space manually:

```bash
# Remove old lane target directories (compilation caches — safe to delete)
rm -rf $APM2_HOME/private/fac/lanes/*/target/

# Remove old evidence logs
rm -rf $APM2_HOME/private/fac/evidence/

# Check disk usage
du -sh $APM2_HOME/private/fac/lanes/*/target/ 2>/dev/null
```

Run manual cleanup when:
- Disk usage exceeds comfortable thresholds
- Before large batch operations
- Periodically via cron/systemd timer

### 3.4 Enqueueing jobs manually

> **PLANNED -- not yet implemented.** The `apm2 fac enqueue` subcommand does
> not exist in the current CLI. Manual job enqueueing is planned for a future
> ticket implementing the FESv1 queue/worker surface. For now, use `apm2 fac gates`
> which handles job creation and execution automatically.

---

## 4. Respond to quarantine and denials

> **PLANNED -- not yet implemented.** Queue-based quarantine and denial
> handling applies to the FESv1 queue/worker surface, which is not yet
> implemented. The current `apm2 fac gates` command executes gates locally
> and does not produce `queue/quarantine/` or `queue/denied/` artifacts.
> The procedures below describe the planned queue-based behavior.

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
ls $APM2_HOME/private/fac/queue/quarantine/

# Inspect a quarantined job (the original spec is preserved)
cat $APM2_HOME/private/fac/queue/quarantine/<job_id>.json

# Check for associated denial receipt
ls $APM2_HOME/private/fac/receipts/ | grep <job_id>
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
ls $APM2_HOME/private/fac/queue/denied/

# Inspect denial reason (sidecar file)
cat $APM2_HOME/private/fac/queue/denied/<job_id>.reason.json
```

### 4.4 Recovering from quarantine/denial (PLANNED)

```bash
# After fixing the root cause, re-run gates locally:
apm2 fac gates

# If lanes are full, free resources (see section 3.3 for manual GC):
du -sh $APM2_HOME/private/fac/lanes/*/target/ 2>/dev/null
# Check for stuck/corrupt lanes:
ls $APM2_HOME/private/fac/lanes/*/lease.v1.json 2>/dev/null
```

---

## 5. Safe lane reset

### 5.1 When to reset a lane

Reset a lane when it enters CORRUPT state or when you need to recover
from a failed cleanup. Common triggers:

- Lane cleanup failed (e.g., permission error, disk full during cleanup)
- Process outlived its lease (cgroup kill timed out)
- Symlink safety check refused deletion (suspicious filesystem state)
- Lane workspace contaminated (unknown files from escaped process)

### 5.2 Check lane state before reset

> **Note:** `apm2 fac lane status` is **PLANNED -- not yet implemented**.
> For now, inspect lane state by examining lease files directly:

```bash
# Check for active leases
for lane in $APM2_HOME/private/fac/lanes/lane-*/; do
  echo "=== $(basename $lane) ==="
  cat "$lane/lease.v1.json" 2>/dev/null || echo "  (no lease)"
done
```

If a lane's lease file indicates a CORRUPT state, proceed with the reset
procedure below.

### 5.3 Perform safe lane reset

> **Note:** `apm2 fac lane reset` is **PLANNED -- not yet implemented**.
> For now, perform manual lane reset carefully:

```bash
# 1. Kill any active systemd unit for the lane (if RUNNING)
systemctl --user stop "apm2-lane-lane-1.scope" 2>/dev/null || true

# 2. Remove the lane workspace and target (safe for compilation caches)
rm -rf $APM2_HOME/private/fac/lanes/lane-1/workspace/
rm -rf $APM2_HOME/private/fac/lanes/lane-1/target/
rm -rf $APM2_HOME/private/fac/lanes/lane-1/logs/

# 3. Remove the lease file
rm -f $APM2_HOME/private/fac/lanes/lane-1/lease.v1.json

# 4. Re-create empty directories
mkdir -p $APM2_HOME/private/fac/lanes/lane-1/{workspace,target,logs}
```

**Caution:** Manual reset does not perform symlink-safe deletion
(`safe_rmtree_v1`) or write reset receipts. When the automated `apm2 fac
lane reset` command is implemented, it will provide these safety guarantees:
1. Symlink-safe recursive deletion (verifies each path component)
2. Refuses to cross filesystem boundaries
3. Refuses to delete unexpected file types (device nodes, sockets)
4. Writes a reset receipt with lane state before and after

**If a lane is in suspicious filesystem state** (unexpected symlinks, device
nodes, etc.), do NOT use `rm -rf`. Investigate manually before proceeding.

### 5.4 Verify lane health after reset

```bash
# Verify lane directory structure was recreated
ls -la $APM2_HOME/private/fac/lanes/lane-1/
# Expected: workspace/, target/, logs/ directories exist; no lease.v1.json

# Optionally pre-warm the reset lane (see section 2.3 for manual warming)
```

### 5.5 Emergency: reset all lanes

```bash
# Reset all lanes (use with caution — see section 5.3 for manual reset steps)
for lane in lane-0 lane-1 lane-2; do
  systemctl --user stop "apm2-lane-${lane}.scope" 2>/dev/null || true
  rm -rf "$APM2_HOME/private/fac/lanes/${lane}/workspace/"
  rm -rf "$APM2_HOME/private/fac/lanes/${lane}/target/"
  rm -rf "$APM2_HOME/private/fac/lanes/${lane}/logs/"
  rm -f  "$APM2_HOME/private/fac/lanes/${lane}/lease.v1.json"
  mkdir -p "$APM2_HOME/private/fac/lanes/${lane}"/{workspace,target,logs}
done

# Verify
ls -la $APM2_HOME/private/fac/lanes/

# Re-warm lanes (see section 2.3 for manual warming procedure)
```

---

## 6. Troubleshooting

### 6.1 Gates fail to start

```
Symptom: apm2 fac gates hangs or returns immediately with no output
```

1. Check lane availability: `ls $APM2_HOME/private/fac/lanes/*/lease.v1.json 2>/dev/null` (PLANNED: `apm2 fac lane status`)
2. Check process health: `systemctl --user status apm2-daemon`
3. Check evidence logs: `ls $APM2_HOME/private/fac/evidence/` and `apm2 fac --json logs`
4. Check disk space: `du -sh $APM2_HOME/private/fac/lanes/*/target/ 2>/dev/null`

### 6.2 Cold-start timeout (240s exceeded)

```
Symptom: Test gate fails with timeout during large compilation
```

1. Pre-warm the lane manually (see section 2.3) (PLANNED: `apm2 fac warm --lane <lane_id>`)
2. If warming itself times out, check if dependencies changed significantly
3. Consider freeing disk space manually (see section 3.3) (PLANNED: `apm2 fac gc`)

### 6.3 nextest not found

```
Symptom: Test gate falls back to cargo test instead of cargo nextest run
```

Fix: `cargo install cargo-nextest`

nextest is the preferred and recommended test runner for FAC evidence gates
(DD-003, RFC-0007). The current implementation falls back to `cargo test
--workspace` when the bounded runner (which uses nextest) is not available.
Install nextest to enable the bounded test execution path with cgroup
resource limits. Fail-closed enforcement (rejecting execution without
nextest) is planned as future work.

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

1. Free disk space manually (see section 3.3) (PLANNED: `apm2 fac gc`)
2. Check lane target directories: `du -sh $APM2_HOME/private/fac/lanes/*/target/`
3. Target directories are compilation caches (safe to delete): `rm -rf $APM2_HOME/private/fac/lanes/<lane_id>/target/` (PLANNED: `apm2 fac lane reset`)
4. Check for orphaned evidence logs: `du -sh $APM2_HOME/private/fac/evidence/`

### 6.6 Stale lease (dead process holding lane)

```
Symptom: Lane shows LEASED but no process is running
```

The scheduler automatically transitions stale leases to CLEANUP then IDLE
when the lease holder's PID is dead. If automatic recovery does not occur,
manually remove the stale lease (PLANNED: `apm2 fac lane reset`):

```bash
rm -f $APM2_HOME/private/fac/lanes/<lane_id>/lease.v1.json
```

### 6.7 Containment violation (process escape)

```
Symptom: Resource accounting shows more consumption than lane limits allow
```

1. Check for sccache daemon: `ps aux | grep sccache`
   - sccache is disabled in default FAC mode; if running, it indicates
     a configuration error
2. Kill escaped processes: `systemctl --user stop "apm2-lane-<lane_id>.scope" 2>/dev/null` then perform manual lane reset (see section 5.3) (PLANNED: `apm2 fac lane reset <lane_id> --force`)
3. Verify RUSTC_WRAPPER is not set in FAC execution environment
4. Check that no ambient ~/.cargo/config.toml overrides FAC policy

---

## 7. Reference: CLI commands

### Currently implemented

| Command | Purpose |
|---------|---------|
| `apm2 fac gates` | Run evidence gates (queue-based, default) |
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

### PLANNED -- not yet implemented

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

## 8. Reference: lane lifecycle state machine

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

## 9. Reference: queue lane priority order

Queue lanes determine scheduling priority (highest first):

1. `stop_revoke` - Stop/revocation commands (highest priority)
2. `control` - Control plane operations
3. `consume` - Consumption operations
4. `replay` - Replay operations
5. `projection_replay` - Projection replay operations
6. `bulk` - Bulk operations (lowest priority, default for gates)

Within a queue lane, `priority` (descending) wins. Ties break by
`enqueue_time` (oldest first), then `job_id` (lexicographic).
