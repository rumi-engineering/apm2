# FAC Daemon and Worker Systemd Services

This runbook covers managed operation of the FAC broker (`apm2-daemon`) and FAC
worker (`apm2 fac worker`) via systemd units.

## Prerequisites

- `systemd` with `systemctl` available.
- `apm2` binary installed at `/usr/local/bin/apm2` (or adjust units manually).
- `HOME` available for user-mode units.
- `APM2_HOME` directory is writable (`~/.apm2` by default).

## 1. Install managed units

### 1.1 User mode (recommended for local operators)

```bash
cd /path/to/apm2-worktree
apm2 daemon install
```

This writes:

- `~/.config/systemd/user/apm2-daemon.service`
- `~/.config/systemd/user/apm2-worker.service`
- `~/.config/systemd/user/apm2-worker@.service`
- `~/.config/systemd/user/apm2-daemon.socket`

and reloads user systemd.

### 1.2 System mode

```bash
sudo cp contrib/systemd/apm2-daemon.service /etc/systemd/system/
sudo cp contrib/systemd/apm2-worker.service /etc/systemd/system/
sudo cp contrib/systemd/apm2-worker@.service /etc/systemd/system/
sudo cp contrib/systemd/apm2-daemon.socket /etc/systemd/system/
sudo systemctl daemon-reload
```

## 2. Service lifecycle

### 2.1 User mode

```bash
systemctl --user enable apm2-daemon.socket
systemctl --user enable apm2-daemon.service
systemctl --user enable apm2-worker.service

systemctl --user start apm2-daemon.socket
systemctl --user start apm2-daemon.service
systemctl --user start apm2-worker.service

systemctl --user status apm2-daemon.service apm2-worker.service apm2-daemon.socket
```

### 2.2 System mode

```bash
sudo systemctl enable apm2-daemon.socket
sudo systemctl enable apm2-daemon.service
sudo systemctl enable apm2-worker.service

sudo systemctl start apm2-daemon.socket
sudo systemctl start apm2-daemon.service
sudo systemctl start apm2-worker.service

sudo systemctl status apm2-daemon.service apm2-worker.service apm2-daemon.socket
```

### 2.3 Stop / restart

```bash
systemctl --user stop apm2-worker.service
systemctl --user stop apm2-daemon.service
systemctl --user restart apm2-daemon.service

# or system mode:
sudo systemctl stop apm2-worker.service
sudo systemctl restart apm2-daemon.service
```

## 3. Linger (user mode)

To keep user units running after SSH logout:

```bash
loginctl enable-linger "$USER"
systemctl --user show-environment | grep -i xdg_runtime_dir
```

Disable when needed:

```bash
loginctl disable-linger "$USER"
```

## 4. Credential provisioning (`LoadCredential=`)

Units expect a GitHub token file at:

```text
~/.apm2/private/creds/gh-token
```

Create and secure it:

```bash
mkdir -p ~/.apm2/private/creds
cat > ~/.apm2/private/creds/gh-token <<'EOF'
<github token>
EOF
chmod 600 ~/.apm2/private/creds/gh-token
```

Reload services after provisioning updates:

```bash
systemctl --user restart apm2-daemon.service
systemctl --user restart apm2-worker.service
```

## 5. Health monitoring (TCK-00600)

### 5.1 Systemd watchdog

Both `apm2-daemon` and `apm2-worker` services use `Type=notify` with
`WatchdogSec=300`. This means:

1. **READY=1** — The process sends `READY=1` to systemd after successful
   initialization (socket bind for daemon, broker connection for worker).
   systemd considers the service "started" only after receiving this signal.

2. **WATCHDOG=1** — The process periodically pings systemd. If no ping arrives
   within `WatchdogSec` (300 seconds / 5 minutes), systemd forcefully restarts
   the service. The ping interval is automatically derived from `WATCHDOG_USEC`
   at half the watchdog timeout (~150 seconds).

3. **STOPPING=1** — Sent during graceful shutdown to inform systemd the process
   is intentionally exiting.

This ensures that both hung processes (no longer making progress) and crashed
processes are restarted automatically.

### 5.2 Health status via `apm2 fac services status`

```bash
apm2 fac services status
apm2 fac services status --json
```

The status output includes per-service fields:

| Field         | Description                                                |
|---------------|------------------------------------------------------------|
| `health`      | `healthy`, `degraded`, or `unhealthy` (deterministic)      |
| `watchdog_sec`| Configured watchdog timeout in seconds (0 if disabled)     |
| `pid`         | Main PID of the service (0 if not running)                 |
| `uptime_sec`  | Seconds since the service started                          |

Overall fields:

| Field              | Description                                           |
|--------------------|-------------------------------------------------------|
| `overall_health`   | Worst-case health across all services                 |
| `worker_heartbeat` | Worker heartbeat file status (see below)              |

Health classification logic:

- **healthy**: service is loaded, active (running), and enabled
- **degraded**: service is loaded but not in the `active` state and not failed
- **unhealthy**: service is in a `failed` state, not loaded, or not found

### 5.3 Worker heartbeat file

The worker writes a JSON heartbeat file at each poll cycle:

```text
~/.apm2/private/fac/worker_heartbeat.json
```

Contents include:

- `pid` — process ID of the worker
- `timestamp_unix` — Unix epoch timestamp of the last poll cycle
- `cycle_count` — monotonically increasing poll cycle counter
- `jobs_completed`, `jobs_denied`, `jobs_quarantined` — cumulative job stats
- `health_status` — self-reported status string (`ok`, etc.)

`apm2 fac services status` reads this file and reports:

- `found` — whether the heartbeat file exists
- `fresh` — whether the last write was within 120 seconds
- `age_secs` — seconds since the last heartbeat write
- `pid` — PID from the heartbeat (can be compared with systemd MainPID)

A stale heartbeat (age > 120s) with an active systemd service suggests the
worker process is alive but not making progress (stuck in a job or I/O wait).

### 5.4 Monitoring checklist

```bash
# Quick health check
apm2 fac services status

# JSON for automated monitoring
apm2 fac services status --json | jq '.overall_health'

# Check if watchdog is active
systemctl --user show apm2-daemon.service -p WatchdogUSec

# View watchdog restarts in journal
journalctl --user -u apm2-daemon.service --grep="watchdog"
journalctl --user -u apm2-worker.service --grep="watchdog"

# Check worker heartbeat freshness
cat ~/.apm2/private/fac/worker_heartbeat.json | jq '.timestamp_unix'
```

## 6. Logging

```bash
journalctl --user -u apm2-daemon.service
journalctl --user -u apm2-worker.service

# system mode
journalctl -u apm2-daemon.service
journalctl -u apm2-worker.service
```

`apm2 fac services status` reports load/active/enabled state, PID, and uptime for
both units.

## 7. Broker IPC reachability checks

The operator socket is expected at:

- User mode: `%t/apm2/operator.sock`
- System mode: `%t/apm2/operator.sock`

Quick checks:

```bash
systemctl --user status apm2-daemon.socket
test -S /run/user/"$(id -u)"/apm2/operator.sock
```

If socket checks fail:

```bash
systemctl --user reset-failed apm2-daemon.service apm2-daemon.socket
systemctl --user restart apm2-daemon.socket
systemctl --user restart apm2-daemon.service
```

## 8. Service command failures (quick triage)

- **`Unit not found`**
  - Confirm the correct file is installed in `~/.config/systemd/user` or
    `/etc/systemd/system`.
  - Run `systemctl daemon-reload` (or `systemctl --user daemon-reload`).

- **`LoadCredential... not found`**
  - Ensure `~/.apm2/private/creds/gh-token` exists and is readable by the service
    user (expected mode `0600`, parent mode `0700`).

- **`failed to reach operator socket`**
  - Confirm `apm2-daemon.service` is active.
  - Confirm socket unit is active/enabled.
  - Run `journalctl` for both `apm2-daemon` and `apm2-worker` for startup errors.

- **`worker repeatedly restarts`**
  - Check queue/runtime permissions under `~/.apm2/private/fac/**`.
  - Check whether credentials are present and readable by the service.
  - Run worker in foreground for diagnostics:

    ```bash
    APM2_HOME=~/.apm2 apm2 fac worker --poll-interval 10
    ```

## 9. Failure mode diagnosis (TCK-00600)

### 9.1 Watchdog-triggered restart

**Symptom**: `journalctl` shows `watchdog timeout` or `Watchdog timestamp expired`.

**Diagnosis**:

1. The process was alive but failed to send `WATCHDOG=1` within 5 minutes.
2. This typically indicates the main loop is blocked (deadlock, slow I/O,
   infinite loop in a job handler).
3. Check the last heartbeat file for workers:
   ```bash
   cat ~/.apm2/private/fac/worker_heartbeat.json
   ```
   A stale `timestamp_unix` confirms the poll loop was stuck.
4. Check daemon logs around the watchdog timeout timestamp for the last
   successful health evaluation cycle.

**Resolution**: The watchdog restart is automatic. If restarts are recurring,
investigate the root cause (resource exhaustion, network partition, disk full).

### 9.2 Service stuck in "activating" state

**Symptom**: `systemctl status` shows `activating (start)` indefinitely.

**Diagnosis**: With `Type=notify`, systemd waits for `READY=1`. If the daemon
fails to bind its socket or the worker fails to connect to the broker, the
`READY=1` signal is never sent.

**Resolution**:

```bash
# Check what the process is waiting on
journalctl --user -u apm2-daemon.service -n 50
# If stuck, stop and investigate
systemctl --user stop apm2-daemon.service
# Verify socket directory and permissions
ls -la /run/user/"$(id -u)"/apm2/
```

### 9.3 Worker heartbeat stale but process active

**Symptom**: `apm2 fac services status` shows worker `health=healthy` but
`worker_heartbeat.fresh=false`.

**Diagnosis**: The worker process is alive (responding to systemd watchdog) but
the poll loop is not completing cycles. Possible causes:

- A long-running job is blocking the synchronous poll loop.
- Disk I/O is slow, causing heartbeat writes to fail silently.
- The heartbeat write path is on a different filesystem that became read-only.

**Resolution**: Check `cycle_count` in the heartbeat file. If it is not
incrementing, the worker is stuck in a job. Check worker logs:

```bash
journalctl --user -u apm2-worker.service -n 100
```

### 9.4 PID mismatch between heartbeat and systemd

**Symptom**: `worker_heartbeat.pid` does not match `systemctl show -p MainPID`.

**Diagnosis**: A previous worker instance wrote the heartbeat and then crashed.
The new instance has a different PID but has not yet overwritten the heartbeat.

**Resolution**: Wait for the next poll cycle. The new worker will overwrite the
heartbeat file with its own PID on the first cycle.
