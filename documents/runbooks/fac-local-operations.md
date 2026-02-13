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

# cargo-nextest (MANDATORY for FAC evidence gates)
cargo install cargo-nextest

# Verify installations
which mold         # /usr/bin/mold
cargo nextest --version
```

**nextest is mandatory.** FAC evidence gates fail closed if nextest is not
installed. There is no fallback to `cargo test` in the default FAC path.

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

**If bounded execution is unavailable**, FAC fails closed with an actionable
error. Fix the user session before proceeding.

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

```bash
apm2 fac lane status
```

Expected output (healthy state):

```
LANE       STATE   JOB_ID   STARTED_AT   TOOLCHAIN   LAST_EXIT
lane-0     IDLE    -        -            -           0 (success)
lane-1     IDLE    -        -            -           0 (success)
lane-2     IDLE    -        -            -           0 (success)
```

JSON output for scripting:

```bash
apm2 fac lane status --json
```

### 2.3 Pre-warm lane targets (reduce cold-start probability)

Cold-start compilation (building all dependencies from scratch) can exceed
the 240-second wall-time limit for the test gate. Pre-warming populates
each lane's target directory with compiled dependencies.

```bash
# Warm all lanes
apm2 fac warm

# Warm a specific lane
apm2 fac warm --lane lane-0
```

Warm writes a `WarmReceiptV1` for auditability. After warming, gate
execution avoids full dependency recompilation.

**When to warm:**
- After initial bootstrap (lanes have empty target directories)
- After a toolchain update (rustc version change invalidates targets)
- After a lane reset (target directory is deleted)
- After major dependency changes in Cargo.toml/Cargo.lock

---

## 3. Start services

### 3.1 Running gates (default queue-based mode)

The default `apm2 fac gates` command uses queue-based execution:

1. Creates a `FacJobSpecV1(kind="gates")` job spec
2. Obtains an RFC-0028 channel context token from the broker
3. Enqueues the job to `queue/pending/`
4. Waits for a worker to claim, execute, and return results

```bash
# Run all evidence gates (queue-based, default)
apm2 fac gates

# Quick mode for development iteration (skips test gate, accepts dirty tree)
apm2 fac gates --quick
```

### 3.2 Running a worker

The worker consumes the local queue and executes jobs in lanes:

```bash
# Run one claim/execute cycle then exit
apm2 fac worker --once

# Run continuously (recommended: use systemd to manage)
apm2 fac worker
```

For production operation, the worker should be managed by systemd:

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

GC reclaims disk space from old logs, stale targets, and expired receipts:

```bash
# Global GC across all FAC-controlled roots
apm2 fac gc

# Lane-scoped GC
apm2 fac gc --lane lane-0
```

GC writes a `GcReceiptV1` recording bytes reclaimed. Run GC when:
- Disk usage exceeds comfortable thresholds
- Before large batch operations
- Periodically via cron/systemd timer

### 3.4 Enqueueing jobs manually

```bash
# Enqueue a job from a spec file
apm2 fac enqueue /path/to/job_spec.json

# Enqueue from stdin
cat job_spec.json | apm2 fac enqueue -

# Cancel a pending job
apm2 fac enqueue --cancel <job_id>
```

---

## 4. Respond to quarantine and denials

### 4.1 Understanding quarantine

A job is moved to `queue/quarantine/` when it fails validation:

- **RFC-0028 channel boundary check failed:** The job's `channel_context_token`
  did not pass `decode_channel_context_token` + `validate_channel_boundary`.
  This means the job was not properly authorized by the broker.
- **Malformed job spec:** The `FacJobSpecV1` could not be parsed with
  bounded deserialization.
- **Integrity check failed:** The `job_spec_digest` does not match the
  computed digest of the job spec contents.

**Quarantined items are preserved for forensics. Never delete them manually.**

### 4.2 Diagnosing quarantined jobs

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

### 4.3 Understanding denials

A job is moved to `queue/denied/` when it fails RFC-0029 queue admission:

- **Budget exceeded:** The job's resource cost exceeds available budget
- **Lane capacity:** No lanes available within the admission window
- **Anti-starvation:** Higher-priority queue lanes are draining first

```bash
# List denied items
ls $APM2_HOME/private/fac/queue/denied/

# Inspect denial reason (sidecar file)
cat $APM2_HOME/private/fac/queue/denied/<job_id>.reason.json
```

### 4.4 Recovering from quarantine/denial

```bash
# After fixing the root cause, re-enqueue the job:
# 1. Create a fresh job spec (do NOT reuse the quarantined file)
apm2 fac gates  # This creates and enqueues a new job automatically

# 2. If lanes are full, free resources:
apm2 fac gc
apm2 fac lane status  # Check for stuck/corrupt lanes
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

```bash
apm2 fac lane status
```

If a lane shows `CORRUPT`:

```
LANE       STATE     JOB_ID          STARTED_AT           TOOLCHAIN   LAST_EXIT
lane-1     CORRUPT   fac-job-abc123  2026-02-13T10:00:00  stable-1.85 -
```

### 5.3 Perform safe lane reset

```bash
# Reset an IDLE or CORRUPT lane
apm2 fac lane reset lane-1

# Reset a RUNNING lane (kills active unit first)
apm2 fac lane reset lane-1 --force
```

The reset command:
1. If `--force`: kills the active systemd unit (KillMode=control-group)
2. Uses `safe_rmtree_v1` for symlink-safe deletion of the lane workspace
3. Verifies each path component is not a symlink before descending
4. Refuses to cross filesystem boundaries
5. Refuses to delete unexpected file types (device nodes, sockets)
6. Writes a reset receipt with the lane state before and after

**If reset fails** (e.g., ambiguous symlink detected):
- The lane remains CORRUPT
- A `refused_delete` receipt is written with the reason
- Manual investigation is required before the lane can be reused

### 5.4 Verify lane health after reset

```bash
apm2 fac lane status
# Expected: lane-1 shows IDLE

# Optionally pre-warm the reset lane
apm2 fac warm --lane lane-1
```

### 5.5 Emergency: reset all lanes

```bash
# Reset all lanes (use with caution)
for lane in lane-0 lane-1 lane-2; do
  apm2 fac lane reset "$lane" --force
done

# Verify
apm2 fac lane status

# Re-warm all lanes
apm2 fac warm
```

---

## 6. Troubleshooting

### 6.1 Gates fail to start

```
Symptom: apm2 fac gates hangs or returns immediately with no output
```

1. Check lane availability: `apm2 fac lane status`
2. Check broker health: `systemctl --user status apm2-daemon`
3. Check queue state: `ls $APM2_HOME/private/fac/queue/pending/`
4. Check logs: `apm2 fac --json logs`

### 6.2 Cold-start timeout (240s exceeded)

```
Symptom: Test gate fails with timeout during large compilation
```

1. Pre-warm the lane: `apm2 fac warm --lane <lane_id>`
2. If warming itself times out, check if dependencies changed significantly
3. Consider running GC to free disk space: `apm2 fac gc`

### 6.3 nextest not found

```
Symptom: FAC fails closed with "nextest not found" error
```

Fix: `cargo install cargo-nextest`

nextest is mandatory for FAC evidence gates (DD-003, RFC-0007). There is
no cargo test fallback.

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

1. Run GC: `apm2 fac gc`
2. Check lane target directories: `du -sh $APM2_HOME/private/fac/lanes/*/target/`
3. Target directories are compilation caches (safe to delete): `apm2 fac lane reset <lane_id>`
4. Check for orphaned evidence logs: `du -sh $APM2_HOME/private/fac/evidence/`

### 6.6 Stale lease (dead process holding lane)

```
Symptom: Lane shows LEASED but no process is running
```

The scheduler automatically transitions stale leases to CLEANUP then IDLE
when the lease holder's PID is dead. If automatic recovery does not occur:

```bash
apm2 fac lane reset <lane_id>
```

### 6.7 Containment violation (process escape)

```
Symptom: Resource accounting shows more consumption than lane limits allow
```

1. Check for sccache daemon: `ps aux | grep sccache`
   - sccache is disabled in default FAC mode; if running, it indicates
     a configuration error
2. Kill escaped processes: `apm2 fac lane reset <lane_id> --force`
3. Verify RUSTC_WRAPPER is not set in FAC execution environment
4. Check that no ambient ~/.cargo/config.toml overrides FAC policy

---

## 7. Reference: CLI commands

| Command | Purpose |
|---------|---------|
| `apm2 fac gates` | Run evidence gates (queue-based, default) |
| `apm2 fac gates --quick` | Quick validation (skips tests, accepts dirty tree) |
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
| `apm2 fac push --ticket <yaml>` | Push and create/update PR |
| `apm2 fac --json logs` | Show log file paths |
| `apm2 fac --json logs --pr <N>` | Show logs for a specific PR |

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
