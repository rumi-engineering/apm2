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

## 5. Logging

```bash
journalctl --user -u apm2-daemon.service
journalctl --user -u apm2-worker.service

# system mode
journalctl -u apm2-daemon.service
journalctl -u apm2-worker.service
```

`apm2 fac services status` reports load/active/enabled state, PID, and uptime for
both units.

## 6. Broker IPC reachability checks

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

## 7. Service command failures (quick triage)

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
