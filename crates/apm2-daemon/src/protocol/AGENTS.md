# Protocol Module

> Unix domain socket protocol stack: framing, handshake, dispatch, and session management.

## Overview

The `protocol` module implements the daemon's IPC protocol stack for CLI-to-daemon communication over Unix domain sockets. It provides the complete protocol layering from transport through application-level dispatch:

```text
+-------------------------------------------+
|           Application Messages             |  Protobuf (messages)
+-------------------------------------------+
|     Privileged / Session Dispatch          |  dispatch / session_dispatch
+-------------------------------------------+
|              Handshake                     |  Hello/HelloAck
+-------------------------------------------+
|               Framing                      |  Length-prefixed (4-byte BE)
+-------------------------------------------+
|            UDS Transport                   |  Unix socket (operator/session)
+-------------------------------------------+
```

### Dual-Socket Privilege Separation (TCK-00249)

The daemon uses two Unix sockets for privilege separation:

- **`operator.sock`** (mode 0600): Privileged operations (ClaimWork, SpawnEpisode, IssueCapability, Shutdown)
- **`session.sock`** (mode 0660): Session-scoped operations (RequestTool, EmitEvent, PublishEvidence, StreamTelemetry)

### Submodules

- `server` -- UDS server with connection management
- `socket_manager` -- Dual-socket manager for privilege separation
- `connection_handler` -- Hello/HelloAck handshake handler
- `framing` -- Length-prefixed frame codec
- `handshake` -- Version negotiation
- `messages` -- Protobuf message types (generated + helpers)
- `dispatch` -- Privileged endpoint dispatcher
- `session_dispatch` -- Session-scoped endpoint dispatcher
- `session_token` -- HMAC-based session token minting/validation
- `credentials` -- Peer credentials extraction (`SO_PEERCRED`)
- `pulse_topic` -- HEF topic grammar and wildcard matching
- `pulse_acl` -- HEF Pulse Plane subscription ACL
- `pulse_outbox` -- HEF Pulse publisher
- `resource_governance` -- Backpressure and drop policy for HEF
- `topic_derivation` -- Deterministic topic derivation for events

## Key Types

### `ProtocolServer`

```rust
pub struct ProtocolServer { /* listener, semaphore, config */ }
```

**Contracts:**

- [CTR-PR01] Removes stale socket file before binding.
- [CTR-PR02] Creates parent directory with mode 0700.
- [CTR-PR03] Socket permissions set to 0600.
- [CTR-PR04] Each connection handled in a separate spawned task.

### `SocketManager`

```rust
pub struct SocketManager { /* operator_listener, session_listener, config */ }
```

**Invariants:**

- [INV-PR01] Operator socket always has mode 0600.
- [INV-PR02] Session socket always has mode 0660.
- [INV-PR03] `is_privileged` determined solely by which socket accepted the connection.

### `PrivilegedDispatcher`

Privileged endpoint dispatcher for RFC-0017 control-plane IPC. Routes privileged messages to typed handlers.

**Contracts:**

- [CTR-PR05] Only accepts messages from operator socket connections.

### `SessionDispatcher`

Session-scoped endpoint dispatcher for RFC-0017. Routes session requests after validating the session token.

**Invariants:**

- [INV-PR04] Session endpoints require valid `session_token`.
- [INV-PR05] Invalid/expired tokens return `SESSION_ERROR_INVALID`.
- [INV-PR06] Token validation uses constant-time HMAC comparison.
- [INV-PR11] In authoritative mode, fail-closed tiers (Tier2/3/4) MUST be denied if neither `AdmissionKernel` nor `LifecycleGate` is wired (TCK-00494 no-bypass invariant). No silent fallback to ungated effect-capable path.
- [INV-PR12] When `AdmissionKernel` is wired and `LifecycleGate` is absent, the `RequestTool` handler MUST invoke `kernel.plan()` and `kernel.execute()` for fail-closed tier requests in authoritative mode. The kernel MUST succeed before broker dispatch proceeds (TCK-00494 kernel invocation invariant).
- [INV-PR13] In authoritative mode, `EmitEvent` and `PublishEvidence` handlers enforce the same kernel/PCAC lifecycle guard as `RequestTool` (TCK-00498). Session endpoints are classified as `Tier2Plus` (fail-closed) since they perform authoritative state mutations (ledger writes, CAS writes).
- [INV-PR14] When `AdmissionKernel` is wired for `EmitEvent`/`PublishEvidence`, the kernel plan/execute lifecycle runs BEFORE the authoritative effect (ledger/CAS write). `AdmissionBundleV1` evidence is persisted before the effect; `AdmissionOutcomeIndexV1` is persisted after (TCK-00498).

**Contracts:**

- [CTR-PR06] Token is validated BEFORE any handler logic executes.
- [CTR-PR07] Messages use bounded decoding (CTR-1603).
- [CTR-PR08] Authority lifecycle guard fires after decode/validate/transport checks but BEFORE PCAC lifecycle and broker dispatch (TCK-00494). Requires at least one authority gate (`AdmissionKernel` or `LifecycleGate`) for fail-closed tier tool requests in authoritative mode.
- [CTR-PR09] When `AdmissionKernel` is wired without `LifecycleGate`, `handle_request_tool` invokes `kernel.plan()` then `kernel.execute()` with fresh clock/session state, denying on any error with `SessionErrorToolNotAllowed`. The kernel result (`AdmissionResultV1`) is persisted to the ledger as a `kernel_tool_actuation` event BEFORE broker dispatch — fail-closed if persistence fails (TCK-00494, SECURITY MAJOR 1 fix).
- [CTR-PR10] `handle_emit_event` and `handle_publish_evidence` invoke the shared `enforce_session_endpoint_kernel_lifecycle` helper after decode/validate checks but BEFORE the authoritative effect (ledger write / CAS write). The helper uses `Tier2Plus` risk tier, domain-separated BLAKE3 intent/effect digests, and enforces governance policy-root prerequisites for fail-closed tiers (TCK-00498, REQ-0026).

### `SessionToken`

```rust
pub struct SessionToken {
    pub session_id: String,
    pub lease_id: String,
    pub spawn_time_ns: u64,
    pub expires_at_ns: u64,
    pub mac: [u8; 32],  // HMAC-SHA256
}
```

**Invariants:**

- [INV-PR07] Domain separation with `apm2.session_token.v1:` prefix.
- [INV-PR08] Token validation uses constant-time comparison (CTR-WH001).

### `TokenMinter`

Mints session tokens with HMAC-SHA256.

### `FrameCodec`

Length-prefixed frame codec. 4-byte big-endian length prefix, max frame 16 MiB.

**Invariants:**

- [INV-PR09] Frame size validated BEFORE allocation (DoS prevention).
- [INV-PR10] Connection closes on any framing or parse error.

### `Hello` / `HelloAck` / `HelloNack`

Handshake messages for version negotiation.

### Protocol Messages (generated)

Protobuf-generated message types including `BoundedDecode` and `Canonicalize` traits. Key message families:

- **Privileged**: `ClaimWorkRequest/Response`, `SpawnEpisodeRequest/Response`, `ShutdownRequest/Response`, `IssueCapabilityRequest/Response`
- **Session**: `RequestToolRequest/Response`, `EmitEventRequest/Response`, `PublishEvidenceRequest/Response`, `StreamTelemetryRequest/Response`
- **HEF Pulse**: `SubscribePulseRequest/Response`, `PulseEnvelopeV1`, `PulseEvent`
- **Process Mgmt**: `ListProcessesRequest/Response`, `StartProcessRequest/Response`
- **Consensus Query**: `ConsensusStatusRequest/Response`, `ConsensusValidatorsRequest/Response`

### `PulsePublisher`

Daemon-owned outbox for HEF Pulse Plane subscriptions.

### `PulseAclEvaluator`

ACL evaluation for Pulse Plane topic subscriptions.

### `TopicPattern` / `TopicDeriver`

Topic grammar, wildcard matching, and deterministic topic derivation.

## Public API

The module provides extensive re-exports. Key entries:

- Server: `ProtocolServer`, `Connection`, `ServerConfig`, `SocketManager`, `SocketType`
- Handshake: `Hello`, `HelloAck`, `HelloNack`, `ServerHandshake`, `ClientHandshake`
- Dispatch: `PrivilegedDispatcher`, `ConnectionContext`, `SessionDispatcher`
- Token: `SessionToken`, `TokenMinter`, `SessionTokenError`
- Framing: `FrameCodec`, `ProtocolError`, `ProtocolResult`
- Messages: All protobuf request/response types
- HEF: `PulsePublisher`, `PulseAclEvaluator`, `TopicPattern`, `SubscriptionRegistry`

## Related Modules

- [`apm2_daemon::session`](../session/AGENTS.md) -- Session state registry queried during dispatch
- [`apm2_daemon::episode`](../episode/AGENTS.md) -- Episode control via privileged dispatch
- [`apm2_daemon::pcac`](../pcac/AGENTS.md) -- PCAC lifecycle gate invoked during session dispatch
- [`apm2_daemon::hsi_contract`](../hsi_contract/AGENTS.md) -- Contract hash exchanged during handshake
- [`apm2_daemon AGENTS.md`](../../AGENTS.md) -- Crate-level architecture

## References

- RFC-0017: Daemon as Control Plane
- RFC-0018: Holonic Event Fabric (HEF) Phase 1
- DD-009: ProtocolServer-only control plane
- AD-DAEMON-002: Wire format specification
- AD-DAEMON-003: Protocol message types
- CTR-1603: Bounded message decoding
- CTR-WH001: Constant-time HMAC comparison
- TCK-00495: Consumption events carry `receipt_hash` and `admission_bundle_digest` for O(1) correlation; `RedundancyReceiptConsumption` extended with binding fields
