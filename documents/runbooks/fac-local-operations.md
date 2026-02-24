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
test runner is available (cgroup v2 + Rust bounded-runner path), FAC uses
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
When bounded execution is selected but the user bus is unavailable,
bounded execution does not fall back. It hard-fails during bounded-runner
preflight. Fix the user session to enable bounded execution before proceeding.

### 1.3 Build and install the apm2 CLI

```bash
cd /path/to/apm2
cargo build --release -p apm2-cli
# Add to PATH or create alias
```

### 1.4 Initialize FAC directory structure

Running `apm2 fac bootstrap --user` performs one-shot idempotent host
provisioning and creates the full FAC directory tree. The same structure is
also created lazily on first use. The full layout under `$APM2_HOME`
(defaults to `~/.apm2`) is:

```
$APM2_HOME/private/fac/
  lanes/              # Execution lanes (bounded workspaces)
  queue/              # Job queue (filesystem-backed)
    pending/
    claimed/
    completed/
    cancelled/
    denied/
    quarantine/
  receipts/           # Content-addressed receipt objects
  locks/lanes/        # Lane and queue locks
  evidence/           # Per-gate evidence logs (written by apm2 fac gates)
  repo_mirror/        # Node-local bare git mirror
  cargo_home/         # FAC-managed CARGO_HOME (isolated from ~/.cargo)
  broker/             # Broker state (policy roots, horizons)
  scheduler/          # Scheduler state persistence
  policy/             # FacPolicyV1 files
  blobs/              # Blob storage
  gate_cache_v2/      # Gate cache for SHA-based result reuse
```

Directories are created with restricted permissions (0o700 in user mode,
0o770 in system mode) via `create_dir_restricted` (no TOCTOU). Policy files
are written 0o600. The operation is additive-only — it never destroys
existing state.

```bash
# User-mode provisioning (recommended for single-operator hosts)
apm2 fac bootstrap --user

# System-mode provisioning (multi-user / system service deployment)
apm2 fac bootstrap --system

# Preview what would be created without making changes
apm2 fac bootstrap --user --dry-run
```

Bootstrap runs five idempotent phases:
1. Create the `$APM2_HOME/private/fac/**` directory tree with restricted permissions
2. Write default `FacPolicyV1` — skipped if the policy file already exists
3. Initialize lane pool
4. Optionally install systemd templates from `contrib/systemd/`
5. Run doctor checks; exit code is gated on the result (INV-BOOT-004, fail-closed)

---

## 2. FESv1 bootstrap and lane management

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

### 2.2 Check and manage lanes

```bash
# Inspect all lanes
apm2 fac lane status

# Initialize lane pool substrate (idempotent)
apm2 fac lane init

# Operator quarantine for a lane
apm2 fac lane mark-corrupt lane-00 --reason "manual quarantine"
```

### 2.3 Pre-warm lane targets

The `apm2 fac warm` command enqueues a lane-scoped pre-warm job. It obtains
an RFC-0028 channel context token from the broker, builds a `FacJobSpecV1`
with warm kind, enqueues it to `queue/pending/`, and optionally waits for a
receipt.

```bash
# Enqueue a warm job on the default lane (bulk) with default phases (fetch,build)
apm2 fac warm

# Wait for the warm job to complete (up to 1200 seconds)
apm2 fac warm --wait

# Specify a custom wait timeout
apm2 fac warm --wait --wait-timeout-secs 600

# Warm specific phases only
apm2 fac warm --phases fetch,build

# Target a specific lane
apm2 fac warm --lane bulk
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--phases <CSV>` | `fetch,build` | Comma-separated list of phases to warm |
| `--lane <NAME>` | `bulk` | Lane to target for the warm job |
| `--wait` | off | Block until receipt is available |
| `--wait-timeout-secs <N>` | `1200` | Maximum seconds to wait when `--wait` is set |

**Returns:** `job_id`, `phases`, `queue_lane`, `policy_hash`.

**Policy enforcement:** `repo_id` allowlist and `bytes_backend` allowlist are
enforced at enqueue time. A minimum of 100 MiB free disk is required to
enqueue a warm job.

---

## 3. Start services

### 3.1 Running gates

The `apm2 fac gates` command enqueues a gates job and waits for completion by
default (`--wait`). Execution is performed by the FAC worker runtime.

1. Validates local preconditions (clean tree in full mode, input bounds)
2. Enqueues bounded evidence execution for the target SHA
3. Worker claims and executes the job under FAC policy/containment
4. Gate artifacts and receipts are written under FAC private state
5. CLI returns a deterministic JSON result

```bash
# Run all evidence gates (waits for completion by default)
apm2 fac gates

# Quick mode for development iteration (skips test gate, accepts dirty tree)
apm2 fac gates --quick

# Return immediately after enqueue
apm2 fac gates --no-wait
```

### 3.2 Running worker services

Use systemd services as the primary worker control surface:

```bash
# user mode
systemctl --user status apm2-worker.service
systemctl --user restart apm2-worker.service

# system mode
sudo systemctl status apm2-worker.service
sudo systemctl restart apm2-worker.service
```

`apm2-worker.service` uses watcher wake signals on `queue/pending` and
`queue/claimed` for steady-state activation. Degraded safety nudges use an
internal bounded interval when watcher delivery is unavailable/overflowed.
Direct `apm2 fac worker` invocation is diagnostics-only.

### 3.3 Running GC (garbage collection)

The `apm2 fac gc` command reclaims disk space across all FAC roots. It is
safe to run at any time and is idempotent.

```bash
# Preview what would be removed without making changes
apm2 fac gc --dry-run

# Run garbage collection
apm2 fac gc

# Enforce a custom free-space floor (default: 1 GB)
apm2 fac gc --min-free-bytes 2147483648
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--dry-run` | off | Print GC plan without removing anything |
| `--min-free-bytes <N>` | `1073741824` (1 GB) | Minimum free bytes floor to enforce |

**GC target kinds and TTLs:**

| Kind | TTL / rule |
|------|-----------|
| `gate_cache` | 30-day TTL; entries at `gate_cache_v2/{sha}/{gate}.yaml` |
| `blob_prune` | Policy-determined |
| `lane_target` | During `apm2 fac doctor --fix` remediation or explicit GC |
| `lane_log` | During `apm2 fac doctor --fix` remediation or explicit GC |
| `quarantine_prune` | Default TTL from policy |
| `denied_prune` | Default TTL from policy |
| `cargo_cache` | Policy-determined |

GC emits a `GcReceiptV1` persisted under `$APM2_HOME/private/fac/receipts/`.

### 3.4 Enqueueing jobs manually (PLANNED)

> **PLANNED -- not yet implemented.** The `apm2 fac enqueue` subcommand does
> not exist in the current CLI. Manual job enqueueing is planned for a future
> ticket implementing the FESv1 queue/worker surface. For now, use `apm2 fac gates`
> for local gate execution.

---

## 4. Respond to quarantine and denials

### 4.1 Understanding quarantine

A job is moved to
`queue/quarantine/` when it fails validation:

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

### 4.3 Understanding denials

A job is moved to
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

### 4.4 Recovering from quarantine/denial

```bash
# After fixing the root cause, re-run gates locally:
apm2 fac gates
```

---

## 5. Safe lane recovery with doctor

### 5.1 When to run host remediation

Run `apm2 fac doctor --fix` when a lane is `CORRUPT` or when recovery
signals appear in services/doctor output. Common triggers:

- Lane cleanup failed (e.g., permission error, disk full during cleanup)
- Process outlived its lease while associated systemd units remained active
- Symlink safety check refused deletion (suspicious filesystem state)
- Tmp residue/corruption prevents lane cleanup

### 5.2 Check lane state before remediation

```bash
# Current lane state and process identity/liveness:
apm2 fac lane status
```

### 5.3 Apply deterministic remediation

```bash
# Single host-side remediation entrypoint:
apm2 fac doctor --fix
```

`apm2 fac doctor --fix` provides these guarantees:
1. Symlink-safe recursive deletion (verifies each path component)
2. Refuses to cross filesystem boundaries
3. Refuses to delete unexpected file types (device nodes, sockets)
4. Runs lane+queue reconcile, bounded tmp scrub, stale log GC, and post-fix checks
5. Fails closed when orphaned units are still active or liveness is inconclusive

---

## 6. Troubleshooting

### 6.1 Gates fail to start

```
Symptom: apm2 fac gates hangs or returns immediately with no output
```

1. Check process health: `systemctl --user status apm2-daemon.service apm2-worker.service`
2. Check evidence logs: `ls "${APM2_HOME:-$HOME/.apm2}/private/fac/evidence/"` and `apm2 fac logs`
3. Check disk space: `df -h` and `du -sh "${APM2_HOME:-$HOME/.apm2}/private/fac/"`

### 6.2 Cold-start timeout (600s exceeded)

```
Symptom: Test gate fails with timeout during large compilation
```

1. Pre-warm the build using the dedicated warm command (preferred path):
   ```bash
   apm2 fac warm --wait --wait-timeout-secs 1200
   ```
2. Fallback: run `cargo build --workspace` manually before running gates
3. If warming itself times out, check if dependencies changed significantly
4. Consider running GC to free disk space (see section 3.3)

### 6.3 bounded test execution unavailable

```
Symptom: Test gate falls back to `cargo test --workspace` instead of bounded
         `cargo nextest run`
```

Fix: Ensure the bounded runner can start. The fallback to `cargo test
--workspace` is expected only when bounded execution prerequisites are
missing (for example cgroup v2 unavailable).

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

1. Run GC to reclaim disk space (primary path):
   ```bash
   apm2 fac gc --dry-run   # preview what would be removed
   apm2 fac gc             # reclaim disk space
   ```
   Use `--min-free-bytes <N>` to enforce a specific free-space floor.
2. Check for orphaned evidence logs: `du -sh "${APM2_HOME:-$HOME/.apm2}/private/fac/evidence/"`
3. Check build target directories: `du -sh target/`
4. Last resort — target directories are compilation caches (safe to delete):
   ```bash
   rm -rf target/
   ```

### 6.6 Stale lease / claimed queue drift

```
Symptom: pending queue drains slowly while claimed jobs remain stuck.
```

1. Check lane state: `apm2 fac lane status`
2. Check queue state: `apm2 fac queue status`
3. Run host reconciliation: `apm2 fac doctor --fix`
4. Confirm worker service is active: `systemctl --user status apm2-worker.service`

### 6.7 Containment violation

```
Symptom: child processes appear outside expected FAC cgroup boundaries.
```

1. Run containment verification: `apm2 fac verify containment`
2. Review worker logs: `journalctl --user -u apm2-worker.service -n 200`
3. If repeated, run remediation: `apm2 fac doctor --fix`

---

## 7. Reference: CLI commands

| Command | Purpose |
|---------|---------|
| `apm2 fac bootstrap` | One-shot host provisioning (`--dry-run`, `--user`, `--system`) |
| `apm2 fac services status` | Systemd-backed daemon/worker service health |
| `apm2 fac doctor` | Check daemon health and prerequisites |
| `apm2 fac doctor --fix` | Deterministic host remediation (doctor-first) |
| `apm2 fac lane status` | Inspect lane lock/lease/liveness state |
| `apm2 fac lane init` | Initialize lane substrate (idempotent) |
| `apm2 fac lane mark-corrupt ...` | Operator quarantine for suspicious lanes |
| `apm2 fac queue status` | Queue forensics (`pending`, `claimed`, `denied`, `quarantine`) |
| `apm2 fac warm` | Enqueue lane pre-warm job |
| `apm2 fac gc` | Reclaim FAC disk state (`--dry-run`, `--min-free-bytes`) |
| `apm2 fac quarantine list|prune` | Inspect/prune denied and quarantined jobs |
| `apm2 fac job show|cancel` | Job lifecycle operations |
| `apm2 fac verify containment` | Check cgroup containment for FAC execution |
| `apm2 fac logs [--pr <N>]` | Discover local pipeline/review log paths |
| `apm2 fac push` | Push + gate + review pipeline orchestration |
| `apm2 fac doctor --pr <N> --fix` | PR-scoped doctor-first remediation and repair convergence |
| `apm2 fac review ...` | Review orchestration and findings/verdict operations |
| `apm2 fac gates` | Internal/advanced gates entrypoint (queue-backed wait model) |
| `apm2 fac worker` | Internal runtime entrypoint (service-managed by `apm2-worker.service`) |

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

Within a queue lane, `priority` (descending) will win. Ties will break by
`enqueue_time` (oldest first), then `job_id` (lexicographic).
