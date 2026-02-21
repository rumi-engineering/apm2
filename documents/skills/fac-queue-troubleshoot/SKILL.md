---
name: fac-queue-troubleshoot
description: Diagnose and fix stuck FAC queue, worker, lane, and review pipeline issues. Use when jobs are pending but not being processed, lanes are stuck, or the worker service is down.
argument-hint: "[--pr N | empty for full queue triage]"
---

orientation: "You are diagnosing why the FAC (Forge Admission Cycle) queue is not making progress. Jobs flow through: pending -> claimed -> running -> completed/denied/quarantine. When this pipeline stalls, the root cause is almost always one of: dead worker service, stale lane lease, or broker unhealthy."

title: FAC Queue Troubleshooting
protocol:
  id: FAC-QUEUE-TRIAGE
  version: 1.0.0
  type: executable_specification

# Decision Tree

## Step 1: Collect Diagnostic Snapshot

Run ALL of these in parallel to get a full picture:

```
apm2 fac queue status                    # Job counts by directory + denial stats
apm2 fac services status                 # Daemon + worker health
apm2 fac lane status                     # Lane states (IDLE/LEASED/RUNNING/CORRUPT)
apm2 fac doctor                          # Overall health checks
apm2 fac broker status                   # Broker liveness + version
```

Key signals to extract:
- `pending.count > 0` with `oldest_enqueue_time` more than 2 minutes old = **stuck**
- `apm2-worker.service` active_state != "active" = **worker down**
- Any lane in LEASED with no PID or dead PID = **stale lease**
- Any lane in CORRUPT = **lane corruption**
- `broker_health.ready != true` = **broker problem**
- `worker_heartbeat.fresh != true` = **worker stalled**

## Step 2: Route by Root Cause

### 2A: Worker Service Dead

**Symptoms**: `apm2-worker.service` shows `inactive (dead)` or `failed`. Pending jobs accumulate. Worker heartbeat may still show fresh (daemon has its own heartbeat).

**Diagnosis**:
```
systemctl --user status apm2-worker.service
```

Look for: `Active: inactive (dead)`, exit code, signal (common: SIGTERM, SIGKILL, OOM).

**Fix**:
```
systemctl --user start apm2-worker.service
```

**Verify**:
```
systemctl --user status apm2-worker.service   # Should show active (running)
apm2 fac queue status                          # pending count should decrease
```

The worker auto-reconciles stale claimed jobs on startup — orphaned claims get requeued.

### 2B: Stale Lane Lease

**Symptoms**: `apm2 fac lane status` shows a lane in `LEASED` state with `pid: null` or a PID that is no longer alive, and `job_id: null`.

**Diagnosis**:
```
apm2 fac lane status          # Check for LEASED lanes with no PID
```

**Fix** (try in order):
1. Restart the worker (it reconciles stale leases on startup):
   ```
   systemctl --user restart apm2-worker.service
   ```
2. If that doesn't clear it, run doctor fix:
   ```
   apm2 fac doctor --fix
   ```

### 2C: Lane Corruption

**Symptoms**: `apm2 fac lane status` shows a lane with `state: CORRUPT` and a `corrupt_reason`.

**Fix**:
```
apm2 fac doctor --fix
```

### 2D: Broker Unhealthy

**Symptoms**: `apm2 fac broker status` shows `ready: false` or stale `age_secs`. Doctor check `broker_socket` fails.

**Fix**: Restart the daemon (broker runs inside the daemon):
```
systemctl --user restart apm2-daemon.service
```

Then restart the worker:
```
systemctl --user restart apm2-worker.service
```

### 2E: All Lanes Busy (Legitimate Backpressure)

**Symptoms**: All lanes show `RUNNING` with valid PIDs and job_ids. Pending jobs exist but lanes are genuinely occupied.

**Action**: This is normal backpressure. Wait for running jobs to complete. Check if jobs are making progress:
```
apm2 fac lane status    # Note the started_at times — very old = possible hang
```

If a lane has been running for >10 minutes on a gates job, investigate:
```
# Check if the PID's process tree is alive and doing work
ps aux | grep <PID>
```

### 2F: High Denial Rate

**Symptoms**: `denied.count` is high relative to `completed.count`. Denial stats show specific reasons.

Common denial reasons and fixes:
- `validation_failed` — job spec malformed or stale; usually harmless, jobs from old pushes
- `token_decode_failed` — signing key mismatch; restart daemon to regenerate keys
- `authority_already_consumed` — replay of consumed token; harmless, means job was already processed
- `token_replay_detected` — duplicate job submission; harmless
- `unsafe_queue_permissions` — queue directory permissions wrong; fix with `chmod 700 ~/.apm2/queue/pending`

### 2G: Jobs Stuck in Claimed

**Symptoms**: `claimed.count > 0` with old `oldest_enqueue_time` (>5 minutes).

**Diagnosis**: A worker claimed jobs but died before completing them.

**Fix**: Restart the worker — it reconciles orphaned claims on startup:
```
systemctl --user restart apm2-worker.service
```

## Step 3: Verify Recovery

After applying fixes, confirm the queue is draining:
```
# Wait 15-30 seconds, then:
apm2 fac queue status        # pending count should be decreasing
apm2 fac lane status         # lanes should be RUNNING or IDLE
apm2 fac services status     # overall_health should be "healthy"
```

## Step 4: PR-Specific Pipeline Stalls

If the queue itself is healthy but a specific PR's review pipeline isn't progressing:

```
apm2 fac review project --pr <N> --emit-errors
```

Key fields:
- `sha` vs `current_head_sha` — if different, reviews ran on an old commit; new push needed or `apm2 fac restart --pr <N>`
- `security` / `quality` — `done:*` means review completed; check verdicts via `apm2 fac review findings --pr <N>`
- `terminal_failure: true` — pipeline gave up; use `apm2 fac restart --pr <N> --force` to retry

To re-trigger the full pipeline for a PR:
```
apm2 fac restart --pr <N>                # Smart restart from optimal point
apm2 fac restart --pr <N> --force        # Full restart regardless of state
```

## Quick Reference: Common Scenarios

| Scenario | Command | Expected Outcome |
|----------|---------|-----------------|
| Check if queue is stuck | `apm2 fac queue status` | pending > 0 with old timestamps = stuck |
| Worker down | `systemctl --user start apm2-worker.service` | Worker starts, drains pending |
| Stale lane | `systemctl --user restart apm2-worker.service` | Reconciles orphaned leases |
| Full triage | Run Step 1 commands in parallel | Identify root cause |
| Disk pressure | `apm2 fac gc --dry-run` then `apm2 fac gc` | Reclaim stale artifacts |
| PR pipeline stuck | `apm2 fac restart --pr <N>` | Re-derive and restart from optimal point |
| Quarantine buildup | `apm2 fac quarantine list` then `apm2 fac quarantine prune` | Clear old quarantined jobs |

## Key Paths

- Queue root: `~/.apm2/queue/` (subdirs: pending, claimed, completed, denied, quarantine, cancelled)
- Lane root: `~/.apm2/private/fac/lanes/` (lane-00, lane-01, lane-02, ...)
- Worker service: `~/.config/systemd/user/apm2-worker.service`
- Daemon service: `~/.config/systemd/user/apm2-daemon.service`
- Worker logs: `journalctl --user -u apm2-worker.service -f`
- Daemon logs: `journalctl --user -u apm2-daemon.service -f`
