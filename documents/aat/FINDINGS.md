# AAT Evidence Report: Full FAC Lifecycle via CLI + Daemon

**Date**: 2026-02-06T15:54:00Z
**Agent**: AAT orchestrator (manual)
**Commit**: a44597c6 (main)
**Binaries**: `target/debug/apm2`, `target/debug/apm2-daemon`

---

## Executive Summary

8 of 10 hypotheses **PASS**. The daemon starts, the CLI connects via dual-socket IPC (operator + session), work can be claimed, episodes spawned, events emitted, and evidence published to CAS. Two areas need attention: the ToolBroker requires initialization before tool requests can execute, and `fac work status` cannot find events using the work_id (schema mismatch or query issue).

---

## Hypothesis Results

| # | Hypothesis | Verdict | Exit Code | Notes |
|---|-----------|---------|-----------|-------|
| H1 | Daemon starts in foreground mode | **PASS** | 0 | Required `chmod 700` on CAS dir first |
| H2 | `apm2 list` connects and returns process list | **PASS** | 0 | Shows 2 configured processes |
| H3 | `apm2 work claim` claims work | **PASS** | 0 | Returns work_id, lease_id, capability manifest hash |
| H4 | `apm2 episode spawn` creates session | **PASS** | 0 | Returns session_id, session_token (JSON), ephemeral handle |
| H5 | `apm2 tool request` executes a tool | **FAIL** | 1 | "broker not initialized: call initialize() first" |
| H6 | `apm2 event emit` emits to ledger | **PASS** | 0 | Event persisted with sequence number |
| H7 | `apm2 evidence publish` stores to CAS | **PASS** | 0 | Artifact stored at `objects/32c8/afd3...`, 22 bytes |
| H8 | `apm2 work status` returns state | **PASS** | 0 | Shows CLAIMED status with actor, role, lease |
| H9 | `apm2 fac work status` reads ledger | **NEEDS_ADJUDICATION** | 12 | "No events found" despite events existing in DB |
| H10 | `apm2 kill` shuts down daemon | **PASS** | 0 | Clean shutdown, sockets removed, projection worker exited |

---

## Detailed Evidence

### H1: Daemon Startup — PASS

**Command**:
```bash
chmod 700 /tmp/apm2/cas
./target/debug/apm2-daemon --config ecosystem.toml --no-daemon \
  --ledger-db /tmp/apm2/ledger.db --cas-path /tmp/apm2/cas \
  --log-level info --no-metrics
```

**Key log lines**:
```
apm2 daemon started (pid: 3135421, operator_socket: "/tmp/apm2/operator.sock", session_socket: "/tmp/apm2/session.sock")
Managing 2 processes
Using with_persistence_and_cas: session dispatcher fully wired cas_path=/tmp/apm2/cas
ProtocolServer control plane started (operator.sock + session.sock only)
```

**Finding**: CAS directory MUST have `0700` permissions or the daemon will refuse to start. This is enforced by design (security hardening) but `mkdir -p` creates with `0755` by default, causing a startup failure on first run. Consider documenting this requirement or auto-fixing permissions in the daemon.

---

### H2: Process Listing — PASS

**Command**:
```bash
./target/debug/apm2 --config ecosystem.toml list
```

**Output**:
```
NAME                 STATE         RUNNING    TOTAL        PID
--------------------------------------------------------------
gemini-cli-1         stopped             0        1          -
claude-code-1        stopped             0        1          -
```

The handshake, protobuf framing, and operator socket connectivity all work correctly. Two processes are configured via `ecosystem.toml` (`claude-code-1` and `gemini-cli-1`).

---

### H3: Work Claiming — PASS

**Command**:
```bash
./target/debug/apm2 --config ecosystem.toml work claim \
  --actor-id aat-agent-001 --role implementer
```

**Output**:
```
Work claimed successfully
  Work ID:                W-a378e3ba-205e-4318-be8b-828dfbf25a81
  Lease ID:               L-63e28e07-59a9-4632-8f76-3cd5038a32f3
  Capability Manifest:    f217057868c0c38274d44498493fee0c3e3145e354ba9bba56d24498f0f743e0
  Policy Resolved Ref:    PolicyResolvedForChangeSet:W-a378e3ba-205e-4318-be8b-828dfbf25a81
  Context Pack Hash:      29c1304c73ed2b70411d797c5205b4184b32ca32befa07a87c128222146a636c
```

**Daemon log**:
```
ClaimWork request received actor_id_hint=aat-agent-001 role=Implementer
Work claimed with policy resolution work_id=W-a378e3ba-... policy_resolved_ref=PolicyResolvedForChangeSet:W-...
Persisted WorkClaimed + WorkTransitioned(Open->Claimed) atomically
```

**Finding**: `--json` flag is advertised in the plan but NOT accepted by the `work` subcommand (exit code 2, "unexpected argument"). JSON output is not available for `work claim` or `work status`.

---

### H4: Episode Spawn — PASS

**Command**:
```bash
./target/debug/apm2 --config ecosystem.toml episode spawn \
  --work-id W-a378e3ba-... --role implementer \
  --lease-id L-63e28e07-... --workspace-root /tmp/apm2
```

**Output**:
```
Episode spawned successfully
  Session ID:           S-d8eca8b5-4181-4f47-bec7-7b506ed26de4
  Capability Manifest:  f217057868c0c38274d44498493fee0c3e3145e354ba9bba56d24498f0f743e0
  Context Pack Sealed:  true
  Ephemeral Handle:     H-cc5de4e6-c130-4bac-8c20-3a0bee41c261
  Session Token:        {"session_id":"S-d8eca8b5-...", "mac":"afa2236760..."}
```

**Daemon log**:
```
episode created episode_id=ep-b942a51d6343fb73-...
episode started session_id=session-1
Persisted SessionStarted + WorkTransitioned(Claimed->InProgress) atomically
```

**Finding**: `--json` flag not accepted on `episode spawn` either. Session token is emitted as part of the human-readable output.

---

### H5: Tool Request — FAIL

**Command**:
```bash
APM2_SESSION_TOKEN='...' ./target/debug/apm2 --config ecosystem.toml tool request \
  --tool-id read --arguments '{"path": "/tmp/apm2"}'
```

**Error**: `broker error: broker not initialized: call initialize() first`

**Daemon log**:
```
RequestTool request received session_id=S-... tool_id=read
ERROR Broker request failed session_id=S-... tool_class=Read error=broker not initialized: call initialize() first
```

**Analysis**: The session socket correctly authenticates the token and parses the tool class (`read` -> `ToolClass::Read`). However, the `ToolBroker` instance in the session dispatcher has not been initialized with an actual executor backend. The broker exists as a mediator but has no concrete tool implementation wired up. This is likely because:
1. Tool execution requires a running episode process (e.g., a Claude/Gemini CLI process), and
2. The broker's `initialize()` method must be called with a concrete adapter when a process starts.

**Additional finding**: Tool class names are case-insensitive and use these aliases:
- `read`, `write`, `execute`/`exec`, `network`/`net`, `git`, `inference`/`llm`, `artifact`/`cas`, `listfiles`/`ls`, `search`/`grep`
- The plan's `list_files` and `file_read` are NOT valid (use `listfiles` and `read`)

---

### H6: Event Emission — PASS

**Command**:
```bash
APM2_SESSION_TOKEN='...' ./target/debug/apm2 --config ecosystem.toml event emit \
  --event-type bug_identified \
  --payload '{"description": "test bug for AAT"}'
```

**Output**:
```
Event emitted successfully
  Event ID:     EVT-5f78e65b-bb3a-44f0-8658-ff0ed4e131fa
  Sequence:     1
  Timestamp:    1770393342486969408 ns
```

**Daemon log**:
```
EmitEvent request received session_id=S-... event_type=bug_identified
Persisted SessionEvent event_id=EVT-5f78e65b-... session_id=S-... event_type=bug_identified actor_id=S-...
EmitEvent persisted to ledger event_id=EVT-... seq=1
```

Event is durably persisted to the SQLite ledger with monotonic sequence numbers.

---

### H7: Evidence Publishing — PASS

**Command**:
```bash
echo "AAT evidence artifact" > /tmp/apm2/test_evidence.txt
APM2_SESSION_TOKEN='...' ./target/debug/apm2 --config ecosystem.toml evidence publish \
  --kind tool-io --path /tmp/apm2/test_evidence.txt
```

**Output**:
```
Evidence published successfully
  Artifact Hash:   32c8afd3045afdc5a669dddffbf1c611c72d580b5f47f31ecaf78fa5b3e893b1
  Storage Path:    evidence/32c8/afd3045afdc5a669dddffbf1c611c72d580b5f47f31ecaf78fa5b3e893b1
  TTL:             604800 seconds
```

**Verified on disk**:
```
/tmp/apm2/cas/objects/32c8/afd3045afdc5a669dddffbf1c611c72d580b5f47f31ecaf78fa5b3e893b1  (22 bytes)
```

CAS uses content-addressed storage with BLAKE3 hashing, sharded by first 4 hex characters.

---

### H8: Work Status — PASS

**Command**:
```bash
./target/debug/apm2 --config ecosystem.toml work status \
  --work-id W-a378e3ba-205e-4318-be8b-828dfbf25a81
```

**Output**:
```
Work Status
  Work ID:   W-a378e3ba-205e-4318-be8b-828dfbf25a81
  Status:    CLAIMED
  Actor ID:  actor:2ef42a9e8d8305eb
  Role:      Implementer
  Lease ID:  L-63e28e07-59a9-4632-8f76-3cd5038a32f3
```

---

### H9: FAC Ledger Inspection — NEEDS_ADJUDICATION

**Command**:
```bash
./target/debug/apm2 --config ecosystem.toml fac --ledger-path /tmp/apm2/ledger.db \
  work status W-a378e3ba-205e-4318-be8b-828dfbf25a81
```

**Error**: `No events found for work_id: W-a378e3ba-205e-4318-be8b-828dfbf25a81`

**Analysis**: The ledger database exists (90KB, confirmed on disk) and the daemon logged successful persistence of:
1. `WorkClaimed + WorkTransitioned(Open->Claimed)` — for work claim
2. `SessionStarted + WorkTransitioned(Claimed->InProgress)` — for episode spawn
3. `SessionEvent (bug_identified)` — for event emit

However, `fac work status` cannot find these events. Possible causes:
1. The `fac` command queries a different table or uses a different schema than the daemon writes
2. The work_id field in the events table may not match the query filter format
3. The `fac` command may read from a separate "FAC events" table distinct from the general ledger

**Finding**: `--ledger-path` must be placed on the `fac` subcommand (before `work`), not after `status`. Incorrect: `fac work status <id> --ledger-path ...`. Correct: `fac --ledger-path ... work status <id>`.

---

### H10: Graceful Shutdown — PASS

**Command**:
```bash
./target/debug/apm2 --config ecosystem.toml kill
```

**Output**: `Daemon shutdown initiated — Message: Shutdown initiated (reason: CLI shutdown request)`

**Daemon log**:
```
Shutdown request received via IPC, initiating graceful shutdown reason=CLI shutdown request
Signaling projection worker shutdown
Projection worker shutting down
Stopping all running processes...
No running processes to stop
Removed operator socket file socket_path=/tmp/apm2/operator.sock
Removed session socket file socket_path=/tmp/apm2/session.sock
Daemon shutdown complete
```

Daemon process exited cleanly (exit code 0). Socket files removed. PID file left on disk (standard behavior).

---

## Additional Findings

### Deprecated/Missing Commands

| Command | Status | Notes |
|---------|--------|-------|
| `apm2 episode list` | **Deprecated** | "not available in protocol-based IPC (DD-009)" |
| `apm2 consensus status` | **Unconfigured** | "consensus subsystem is not configured" (expected) |

### CLI Flag Issues

| Issue | Severity | Details |
|-------|----------|---------|
| `--json` flag not on `work` subcommand | Minor | `work claim` and `work status` don't accept `--json` |
| `--json` flag not on `episode spawn` | Minor | Must parse human-readable output |
| `--ledger-path` position | Minor | Must be before subcommand (`fac --ledger-path ... work status`) |
| Tool class naming | Minor | CLI uses `read`/`write` but plan assumed `file_read`/`list_files` |

### Security Properties Verified

1. CAS directory enforces `0700` permissions (fail-closed)
2. Session tokens use HMAC-authenticated JSON with expiry
3. Operator socket uses `0600` permissions (owner-only)
4. Session socket uses `0660` permissions (owner + group)
5. Unknown tool classes are denied (fail-closed, TCK-00260)
6. Protobuf framing with 16MiB max frame size

### Daemon Behavior Properties

1. Zero panics observed during entire lifecycle
2. Clean startup with crash recovery check (0 sessions recovered)
3. Atomic event persistence (WorkClaimed + WorkTransitioned in single transaction)
4. Projection worker starts disabled when no adapter configured
5. Divergence watchdog correctly disabled when not configured
6. Connection lifecycle properly tracked with connection IDs

---

## Actionable Items — Ticket Decomposition (RFC-0018)

Deep code analysis identified **6 blockers** and **7 major** deficiencies. These have been decomposed into 8 tickets (TCK-00396 through TCK-00403):

### Blockers (Tickets Filed)

| Ticket | Title | Blocker | Dependencies |
|--------|-------|---------|-------------|
| **TCK-00396** | Complete HarnessHandle with real PTY storage | HarnessHandle is Placeholder-only — send_input/terminate are stubs | None |
| **TCK-00397** | Add adapter_profile_hash to SpawnEpisodeRequest/EpisodeEnvelope | No adapter binding in spawn flow | None |
| **TCK-00398** | Unify ledger write/read schemas (ledger_events vs events) | Daemon writes to wrong table for CLI reads | None |
| **TCK-00399** | Wire AdapterRegistry into SpawnEpisode to spawn agent processes | No agent process is spawned after SpawnEpisode | TCK-00396, TCK-00397 |
| **TCK-00400** | Implement weighted random adapter profile selection | No model selection/rotation mechanism exists | TCK-00397, TCK-00399 |
| **TCK-00401** | Initialize ToolBroker with manifest and policy in production | Broker never initialized — all tool requests fail | TCK-00397 |
| **TCK-00402** | Implement CodexCliAdapter with JSONL parser | No Codex-specific adapter despite codex-cli-v1 profile existing | TCK-00396, TCK-00399 |
| **TCK-00403** | End-to-end FAC lifecycle integration test | Validates all fixes work together | TCK-00396..TCK-00401 |

### Dependency Graph

```
TCK-00396 (HarnessHandle) ──┐
                             ├──> TCK-00399 (Wire Adapter) ──┐
TCK-00397 (Proto field)   ──┤                                ├──> TCK-00400 (Model Selection)
                             │                                │
                             └──> TCK-00401 (Broker Init)     │
                                                              ├──> TCK-00403 (E2E Test)
TCK-00398 (Ledger Schema) ───────────────────────────────────┘

TCK-00396 ──> TCK-00399 ──> TCK-00402 (Codex Adapter)
```

### Wave Execution Plan

- **Wave 1 (parallel)**: TCK-00396, TCK-00397, TCK-00398 — no dependencies, can run simultaneously
- **Wave 2 (parallel)**: TCK-00399, TCK-00401 — depend on Wave 1
- **Wave 3 (parallel)**: TCK-00400, TCK-00402 — depend on Wave 2
- **Wave 4**: TCK-00403 — validates everything

### Additional Findings (Not Yet Ticketed)

1. **JSON output parity**: Add `--json` flag to `work claim`, `work status`, and `episode spawn` for machine-readable output (needed for automation/scripting).
2. **CAS directory auto-fix**: Consider having the daemon `chmod 0700` the CAS directory at startup rather than refusing to start, or document the requirement prominently.
3. **Coordinator uses SystemTime::now()** for HTF authority ticks — violates HTF contract.
4. **No lease expiry / heartbeat** — crashed coordinator leaves work claimed permanently.
5. **Non-Reviewer roles get permissive fallback manifest** instead of fail-closed.

---

## Environment

```
OS: Linux 6.8.0-90-generic (Ubuntu)
Rust: stable (dev profile, unoptimized + debuginfo)
Build time: 26.80s (clean incremental)
Daemon PID: 3135421
Ledger DB: /tmp/apm2/ledger.db (90KB after test)
CAS: /tmp/apm2/cas/ (1 artifact, 22 bytes)
```
