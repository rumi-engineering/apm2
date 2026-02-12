# Telemetry Module

> Cgroup-based resource telemetry collection with ring buffer storage and budget integration.

## Overview

The `telemetry` module provides per-episode resource metric collection from Linux cgroups v2 (primary) or `/proc` (fallback). Metrics include CPU time, memory usage, and I/O bytes. The collection architecture uses a layered design with policy-driven sampling and ring buffer storage.

```text
TelemetryCollector
    |
    v
CgroupReader          <-- Primary: per-episode cgroups v2
    |
    v
ProcReader             <-- Fallback: /proc/{pid}/ (degraded mode)
    |
    v
TelemetryFrame         <-- Captured metrics with timestamps
```

### Submodules

- `cgroup` -- Cgroups v2 reader and scope management
- `stats` -- CPU, memory, and I/O statistics types
- `proc_fallback` -- `/proc` fallback for degraded mode
- `frame` -- `TelemetryFrame` type for captured metrics
- `policy` -- `TelemetryPolicy` configuration
- `handle` -- `TelemetryHandle` for active collection sessions
- `collector` -- `TelemetryCollector` implementation
- `reviewer` -- Reviewer telemetry writer and projection events

## Key Types

### `TelemetryCollector`

```rust
pub struct TelemetryCollector { /* policy, shared state */ }
```

Main collector that periodically reads metrics, computes deltas, and pushes frames to ring buffers.

**Contracts:**

- [CTR-TL01] Reports `cpu_ms` and `bytes_io` to `BudgetTracker` for budget enforcement.
- [CTR-TL02] Triggers stop if budget is exhausted.

### `TelemetryFrame`

```rust
pub struct TelemetryFrame {
    pub episode_id: EpisodeId,
    pub seq: u64,
    pub ts_mono: u64,
    pub cpu_ns: u64,
    pub cpu_user_ns: u64,
    pub cpu_system_ns: u64,
    pub mem_rss_bytes: u64,
    pub mem_peak_bytes: u64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub source: MetricSource,
    pub o11y_flags: O11yFlags,
}
```

**Invariants:**

- [INV-TL01] Sequence numbers are monotonically increasing per episode.
- [INV-TL02] All values bounded to prevent overflow (`MAX_FRAME_NS`, `MAX_FRAME_BYTES`).
- [INV-TL03] Timestamps are monotonic (from `CLOCK_MONOTONIC`).

### `O11yFlags`

```rust
pub struct O11yFlags {
    pub high_frequency: bool,
    pub promoted: bool,
    pub degraded: bool,
    pub initial: bool,
    pub terminal: bool,
}
```

Observability flags indicating collection mode and special conditions.

### `CgroupReader`

Reads metrics from cgroups v2 hierarchy (`/sys/fs/cgroup/apm2.slice/episode-{uuid}.scope/`).

**Invariants:**

- [INV-TL04] Cgroup paths are bounded to `MAX_CGROUP_PATH_LEN`.
- [INV-TL05] Telemetry file reads bounded to `MAX_TELEMETRY_FILE_SIZE`.

### `ProcReader`

Fallback reader using `/proc/{pid}/` when cgroup isolation is unavailable.

### `TelemetryPolicy`

```rust
pub struct TelemetryPolicy {
    pub sample_period_ms: u64,
    pub ring_buffer_capacity: usize,
    pub high_freq_threshold_percent: u8,
    pub promote_triggers: PromoteTriggers,
}
```

Built via `TelemetryPolicyBuilder`. Controls sampling interval, buffer size, and high-frequency promotion.

**Invariants:**

- [INV-TL06] Sample period bounded to `[MIN_SAMPLE_PERIOD_MS, MAX_SAMPLE_PERIOD_MS]`.
- [INV-TL07] Ring buffer capacity bounded to `[MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY]`.

### `TelemetryHandle`

Handle for active collection sessions. Tracks episode ID, PID, and sequence counter.

### `ResourceStats` / `CpuStats` / `MemoryStats` / `IoStats`

Typed statistics containers with metric source tracking.

### `ReviewerTelemetryWriter`

Writes reviewer telemetry events to NDJSON files with rotation.

## Public API

- `TelemetryCollector`, `TelemetryError`, `new_shared_collector`
- `TelemetryFrame`, `TelemetryFrameBuilder`, `O11yFlags`
- `TelemetryPolicy`, `TelemetryPolicyBuilder`, `PromoteTriggers`
- `TelemetryHandle`, `TelemetryHandleSnapshot`
- `CgroupReader`, `CgroupError`, `OsResourceLimits`
- `ProcReader`, `ProcError`
- `ResourceStats`, `CpuStats`, `MemoryStats`, `IoStats`, `MetricSource`
- `ReviewerTelemetryWriter`, `ReviewerProjectionEvent`, `ProjectionSummary`
- `create_episode_scope`, `remove_episode_scope`, `is_cgroup_v2_available`

## Related Modules

- [`apm2_daemon::episode`](../episode/AGENTS.md) -- Episodes that produce telemetry
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- `StreamTelemetry` session endpoint
- [`apm2_daemon::evidence`](../evidence/AGENTS.md) -- Telemetry frames stored in flight recorder

## References

- AD-TEL-001: Telemetry collection via cgroups v2
- AD-CGROUP-001: Per-episode cgroup hierarchy
- CTR-DAEMON-005: `TelemetryCollector` and frame streaming
