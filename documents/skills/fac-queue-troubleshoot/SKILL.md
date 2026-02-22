---
name: fac-queue-troubleshoot
description: Diagnose and fix stuck FAC queue, worker, lane, and review pipeline issues. Use when jobs are pending but not being processed, lanes are stuck, or worker health is degraded.
argument-hint: "[--pr N | empty for full queue triage]"
---

orientation: "You are diagnosing FAC queue progress stalls. Runtime queue pickup is event-driven, claimed self-heal is runtime-safe and claimed-only, and broad host remediation is doctor-first. Prefer deterministic, idempotent remediation: `apm2 fac doctor --fix` for host scope and `apm2 fac doctor --pr <N> --fix` for PR scope."

title: FAC Queue Troubleshooting
protocol:
  id: FAC-QUEUE-TRIAGE
  version: 1.1.0
  type: executable_specification

## Step 1: Collect Diagnostic Snapshot

Run all of these in parallel:

```bash
apm2 fac queue status
apm2 fac services status
apm2 fac lane status
apm2 fac doctor
apm2 fac broker status
```

Key signals:
- `pending.count > 0` with old `oldest_enqueue_time` => queue is stuck.
- worker service health not `healthy` => runtime execution unavailable/degraded.
- any lane in `CORRUPT` => deterministic doctor remediation required.
- stale/dead active lane identity => lifecycle or lease drift.
- `worker_heartbeat.fresh != true` with active worker => runtime loop stalled/degraded.

## Step 2: Route by Root Cause

### 2A: Worker Service Dead

Symptoms: worker service is `inactive`/`failed`, pending jobs accumulate.

Commands:
```bash
systemctl --user status apm2-worker.service
systemctl --user start apm2-worker.service
apm2 fac doctor --fix
```

Why: service start restores runtime; `doctor --fix` performs bounded deterministic remediation for stale claims/lanes.

### 2B: Stale Lease or Lane Drift

Symptoms: `LEASED` lane with dead/missing process identity, or queue/claimed drift.

Command:
```bash
apm2 fac doctor --fix
```

Notes:
- Do not rely on worker restarts as the primary remediation path.
- Repeat `apm2 fac doctor --fix` safely; it is expected to converge idempotently.

### 2C: Lane Corruption

Symptoms: lane state is `CORRUPT`.

Command:
```bash
apm2 fac doctor --fix
```

### 2D: Broker/Daemon Unhealthy

Symptoms: `apm2 fac broker status` not ready, or doctor reports broker/control-plane failures.

Commands:
```bash
systemctl --user restart apm2-daemon.service
systemctl --user restart apm2-worker.service
apm2 fac doctor --fix
```

### 2E: Legitimate Backpressure

Symptoms: all lanes are RUNNING with valid identity and queue still has pending work.

Action: observe progress first; only remediate when activity stalls or health degrades.

```bash
apm2 fac lane status
apm2 fac services status
```

### 2F: High Denial Rate

Symptoms: `denied.count` high vs `completed.count`.

Action:
- inspect denial reason distribution in `apm2 fac queue status`.
- if host/runtime drift exists, run `apm2 fac doctor --fix`.
- if failures are workload-specific, route to implementor/remediation flow.

### 2G: Jobs Stuck in Claimed

Symptoms: `claimed.count > 0` remains non-zero with old enqueue age and no forward progress.

Command:
```bash
apm2 fac doctor --fix
```

Notes:
- Runtime claimed self-heal is wake-driven, but doctor remains the broad remediation surface.
- Prefer doctor over manual ad-hoc restarts for convergence.

## Step 3: Verify Recovery

After remediation:

```bash
apm2 fac queue status
apm2 fac lane status
apm2 fac services status
apm2 fac doctor
```

Expected:
- pending/claimed trends move toward zero or stable bounded backpressure.
- service health returns to healthy or explicit degraded diagnostics are actionable.

## Step 4: PR-Scoped Pipeline Stalls

If host queue is healthy but one PR is stalled:

```bash
apm2 fac doctor --pr <N>
```

Use `recommended_action` as the control signal:
- `fix` => run `apm2 fac doctor --pr <N> --fix`.
- `dispatch_implementor` => execute `recommended_action.command` (typically findings retrieval) and dispatch implementor remediation.
- `wait` => optionally block on state change with:
  - `apm2 fac doctor --pr <N> --wait-for-recommended-action`

Important:
- Do not use removed legacy commands (`fac recover`, `fac restart`, `fac review run`, `fac review restart`).
- Do not use non-existent flags like `--force`/`--refresh-identity` with doctor.

## Quick Reference

| Scenario | Command | Expected Outcome |
|----------|---------|-----------------|
| Queue appears stuck | `apm2 fac queue status` | Detects pending/claimed drift and denial patterns |
| Worker down | `systemctl --user start apm2-worker.service` + `apm2 fac doctor --fix` | Service restored + deterministic remediation |
| Lane corrupt/stale | `apm2 fac doctor --fix` | Lane/queue convergence with explicit diagnostics |
| PR pipeline stalled | `apm2 fac doctor --pr <N>` then `apm2 fac doctor --pr <N> --fix` as directed | PR-scoped repair cycle converges |
| Disk/cache pressure | `apm2 fac gc --dry-run` then `apm2 fac gc` | Reclaims stale artifacts |
| Quarantine buildup | `apm2 fac quarantine list` then `apm2 fac quarantine prune` | Removes stale quarantine artifacts |

## Key Paths

- Queue root: `~/.apm2/queue/` (`pending`, `claimed`, `completed`, `denied`, `quarantine`, `cancelled`)
- Lane root: `~/.apm2/private/fac/lanes/`
- Worker service: `~/.config/systemd/user/apm2-worker.service`
- Daemon service: `~/.config/systemd/user/apm2-daemon.service`
- Worker logs: `journalctl --user -u apm2-worker.service -f`
- Daemon logs: `journalctl --user -u apm2-daemon.service -f`
